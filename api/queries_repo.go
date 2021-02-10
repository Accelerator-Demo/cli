package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cli/cli/internal/ghinstance"
	"github.com/cli/cli/internal/ghrepo"
	"github.com/shurcooL/githubv4"
)

// Repository contains information about a GitHub repo
type Repository struct {
	ID          string
	Name        string
	Description string
	URL         string
	CloneURL    string
	CreatedAt   time.Time
	Owner       RepositoryOwner

	IsPrivate        bool
	HasIssuesEnabled bool
	HasWikiEnabled   bool
	ViewerPermission string
	DefaultBranchRef BranchRef

	Parent *Repository

	MergeCommitAllowed bool
	RebaseMergeAllowed bool
	SquashMergeAllowed bool

	// pseudo-field that keeps track of host name of this repo
	hostname string
}

type TemplateRepository struct {
	NameWithOwner string
	Description   string
	IsTemplate    bool
	Url           string
}

// RepositoryOwner is the owner of a GitHub repository
type RepositoryOwner struct {
	Login string
}

// BranchRef is the branch name in a GitHub repository
type BranchRef struct {
	Name string
}

// RepoOwner is the login name of the owner
func (r Repository) RepoOwner() string {
	return r.Owner.Login
}

// RepoName is the name of the repository
func (r Repository) RepoName() string {
	return r.Name
}

// RepoHost is the GitHub hostname of the repository
func (r Repository) RepoHost() string {
	return r.hostname
}

// IsFork is true when this repository has a parent repository
func (r Repository) IsFork() bool {
	return r.Parent != nil
}

// ViewerCanPush is true when the requesting user has push access
func (r Repository) ViewerCanPush() bool {
	switch r.ViewerPermission {
	case "ADMIN", "MAINTAIN", "WRITE":
		return true
	default:
		return false
	}
}

// ViewerCanTriage is true when the requesting user can triage issues and pull requests
func (r Repository) ViewerCanTriage() bool {
	switch r.ViewerPermission {
	case "ADMIN", "MAINTAIN", "WRITE", "TRIAGE":
		return true
	default:
		return false
	}
}

func GitHubRepo(client *Client, repo ghrepo.Interface) (*Repository, error) {
	query := `
	fragment repo on Repository {
		id
		name
		owner { login }
		hasIssuesEnabled
		description
		hasWikiEnabled
		viewerPermission
		defaultBranchRef {
			name
		}
	}

	query RepositoryInfo($owner: String!, $name: String!) {
		repository(owner: $owner, name: $name) {
			...repo
			parent {
				...repo
			}
			mergeCommitAllowed
			rebaseMergeAllowed
			squashMergeAllowed
		}
	}`
	variables := map[string]interface{}{
		"owner": repo.RepoOwner(),
		"name":  repo.RepoName(),
	}

	result := struct {
		Repository Repository
	}{}
	err := client.GraphQL(repo.RepoHost(), query, variables, &result)

	if err != nil {
		return nil, err
	}

	return InitRepoHostname(&result.Repository, repo.RepoHost()), nil
}

func RepoDefaultBranch(client *Client, repo ghrepo.Interface) (string, error) {
	if r, ok := repo.(*Repository); ok && r.DefaultBranchRef.Name != "" {
		return r.DefaultBranchRef.Name, nil
	}

	r, err := GitHubRepo(client, repo)
	if err != nil {
		return "", err
	}
	return r.DefaultBranchRef.Name, nil
}

func CanPushToRepo(httpClient *http.Client, repo ghrepo.Interface) (bool, error) {
	if r, ok := repo.(*Repository); ok && r.ViewerPermission != "" {
		return r.ViewerCanPush(), nil
	}

	apiClient := NewClientFromHTTP(httpClient)
	r, err := GitHubRepo(apiClient, repo)
	if err != nil {
		return false, err
	}
	return r.ViewerCanPush(), nil
}

// RepoParent finds out the parent repository of a fork
func RepoParent(client *Client, repo ghrepo.Interface) (ghrepo.Interface, error) {
	var query struct {
		Repository struct {
			Parent *struct {
				Name  string
				Owner struct {
					Login string
				}
			}
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner": githubv4.String(repo.RepoOwner()),
		"name":  githubv4.String(repo.RepoName()),
	}

	gql := graphQLClient(client.http, repo.RepoHost())
	err := gql.QueryNamed(context.Background(), "RepositoryFindParent", &query, variables)
	if err != nil {
		return nil, err
	}
	if query.Repository.Parent == nil {
		return nil, nil
	}

	parent := ghrepo.NewWithHost(query.Repository.Parent.Owner.Login, query.Repository.Parent.Name, repo.RepoHost())
	return parent, nil
}

// RepoNetworkResult describes the relationship between related repositories
type RepoNetworkResult struct {
	ViewerLogin  string
	Repositories []*Repository
}

// RepoNetwork inspects the relationship between multiple GitHub repositories
func RepoNetwork(client *Client, repos []ghrepo.Interface) (RepoNetworkResult, error) {
	var hostname string
	if len(repos) > 0 {
		hostname = repos[0].RepoHost()
	}

	queries := make([]string, 0, len(repos))
	for i, repo := range repos {
		queries = append(queries, fmt.Sprintf(`
		repo_%03d: repository(owner: %q, name: %q) {
			...repo
			parent {
				...repo
			}
		}
		`, i, repo.RepoOwner(), repo.RepoName()))
	}

	// Since the query is constructed dynamically, we can't parse a response
	// format using a static struct. Instead, hold the raw JSON data until we
	// decide how to parse it manually.
	graphqlResult := make(map[string]*json.RawMessage)
	var result RepoNetworkResult

	err := client.GraphQL(hostname, fmt.Sprintf(`
	fragment repo on Repository {
		id
		name
		owner { login }
		viewerPermission
		defaultBranchRef {
			name
		}
		isPrivate
	}
	query RepositoryNetwork {
		viewer { login }
		%s
	}
	`, strings.Join(queries, "")), nil, &graphqlResult)
	graphqlError, isGraphQLError := err.(*GraphQLErrorResponse)
	if isGraphQLError {
		// If the only errors are that certain repositories are not found,
		// continue processing this response instead of returning an error
		tolerated := true
		for _, ge := range graphqlError.Errors {
			if ge.Type != "NOT_FOUND" {
				tolerated = false
			}
		}
		if tolerated {
			err = nil
		}
	}
	if err != nil {
		return result, err
	}

	keys := make([]string, 0, len(graphqlResult))
	for key := range graphqlResult {
		keys = append(keys, key)
	}
	// sort keys to ensure `repo_{N}` entries are processed in order
	sort.Strings(keys)

	// Iterate over keys of GraphQL response data and, based on its name,
	// dynamically allocate the target struct an individual message gets decoded to.
	for _, name := range keys {
		jsonMessage := graphqlResult[name]
		if name == "viewer" {
			viewerResult := struct {
				Login string
			}{}
			decoder := json.NewDecoder(bytes.NewReader([]byte(*jsonMessage)))
			if err := decoder.Decode(&viewerResult); err != nil {
				return result, err
			}
			result.ViewerLogin = viewerResult.Login
		} else if strings.HasPrefix(name, "repo_") {
			if jsonMessage == nil {
				result.Repositories = append(result.Repositories, nil)
				continue
			}
			var repo Repository
			decoder := json.NewDecoder(bytes.NewReader(*jsonMessage))
			if err := decoder.Decode(&repo); err != nil {
				return result, err
			}
			result.Repositories = append(result.Repositories, InitRepoHostname(&repo, hostname))
		} else {
			return result, fmt.Errorf("unknown GraphQL result key %q", name)
		}
	}
	return result, nil
}

func InitRepoHostname(repo *Repository, hostname string) *Repository {
	repo.hostname = hostname
	if repo.Parent != nil {
		repo.Parent.hostname = hostname
	}
	return repo
}

// repositoryV3 is the repository result from GitHub API v3
type repositoryV3 struct {
	NodeID    string
	Name      string
	CreatedAt time.Time `json:"created_at"`
	CloneURL  string    `json:"clone_url"`
	Owner     struct {
		Login string
	}
}

// ForkRepo forks the repository on GitHub and returns the new repository
func ForkRepo(client *Client, repo ghrepo.Interface) (*Repository, error) {
	path := fmt.Sprintf("repos/%s/forks", ghrepo.FullName(repo))
	body := bytes.NewBufferString(`{}`)
	result := repositoryV3{}
	err := client.REST(repo.RepoHost(), "POST", path, body, &result)
	if err != nil {
		return nil, err
	}

	return &Repository{
		ID:        result.NodeID,
		Name:      result.Name,
		CloneURL:  result.CloneURL,
		CreatedAt: result.CreatedAt,
		Owner: RepositoryOwner{
			Login: result.Owner.Login,
		},
		ViewerPermission: "WRITE",
		hostname:         repo.RepoHost(),
	}, nil
}

// RepoFindForks finds forks of the repo that are affiliated with the viewer
func RepoFindForks(client *Client, repo ghrepo.Interface, limit int) ([]*Repository, error) {
	result := struct {
		Repository struct {
			Forks struct {
				Nodes []Repository
			}
		}
	}{}

	variables := map[string]interface{}{
		"owner": repo.RepoOwner(),
		"repo":  repo.RepoName(),
		"limit": limit,
	}

	if err := client.GraphQL(repo.RepoHost(), `
	query RepositoryFindFork($owner: String!, $repo: String!, $limit: Int!) {
		repository(owner: $owner, name: $repo) {
			forks(first: $limit, affiliations: [OWNER, COLLABORATOR]) {
				nodes {
					id
					name
					owner { login }
					url
					viewerPermission
				}
			}
		}
	}
	`, variables, &result); err != nil {
		return nil, err
	}

	var results []*Repository
	for _, r := range result.Repository.Forks.Nodes {
		// we check ViewerCanPush, even though we expect it to always be true per
		// `affiliations` condition, to guard against versions of GitHub with a
		// faulty `affiliations` implementation
		if !r.ViewerCanPush() {
			continue
		}
		results = append(results, InitRepoHostname(&r, repo.RepoHost()))
	}

	return results, nil
}

type RepoMetadataResult struct {
	AssignableUsers []RepoAssignee
	Labels          []RepoLabel
	Projects        []RepoProject
	Milestones      []RepoMilestone
	Teams           []OrgTeam
}

func (m *RepoMetadataResult) MembersToIDs(names []string) ([]string, error) {
	var ids []string
	for _, assigneeLogin := range names {
		found := false
		for _, u := range m.AssignableUsers {
			if strings.EqualFold(assigneeLogin, u.Login) {
				ids = append(ids, u.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("'%s' not found", assigneeLogin)
		}
	}
	return ids, nil
}

func (m *RepoMetadataResult) TeamsToIDs(names []string) ([]string, error) {
	var ids []string
	for _, teamSlug := range names {
		found := false
		slug := teamSlug[strings.IndexRune(teamSlug, '/')+1:]
		for _, t := range m.Teams {
			if strings.EqualFold(slug, t.Slug) {
				ids = append(ids, t.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("'%s' not found", teamSlug)
		}
	}
	return ids, nil
}

func (m *RepoMetadataResult) LabelsToIDs(names []string) ([]string, error) {
	var ids []string
	for _, labelName := range names {
		found := false
		for _, l := range m.Labels {
			if strings.EqualFold(labelName, l.Name) {
				ids = append(ids, l.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("'%s' not found", labelName)
		}
	}
	return ids, nil
}

func (m *RepoMetadataResult) ProjectsToIDs(names []string) ([]string, error) {
	var ids []string
	for _, projectName := range names {
		found := false
		for _, p := range m.Projects {
			if strings.EqualFold(projectName, p.Name) {
				ids = append(ids, p.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("'%s' not found", projectName)
		}
	}
	return ids, nil
}

func ProjectsToPaths(projects []RepoProject, names []string) ([]string, error) {
	var paths []string
	for _, projectName := range names {
		found := false
		for _, p := range projects {
			if strings.EqualFold(projectName, p.Name) {
				// format of ResourcePath: /OWNER/REPO/projects/PROJECT_NUMBER or /orgs/ORG/projects/PROJECT_NUMBER
				// required format of path: OWNER/REPO/PROJECT_NUMBER or ORG/PROJECT_NUMBER
				var path string
				pathParts := strings.Split(p.ResourcePath, "/")
				if pathParts[1] == "orgs" {
					path = fmt.Sprintf("%s/%s", pathParts[2], pathParts[4])
				} else {
					path = fmt.Sprintf("%s/%s/%s", pathParts[1], pathParts[2], pathParts[4])
				}
				paths = append(paths, path)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("'%s' not found", projectName)
		}
	}
	return paths, nil
}

func (m *RepoMetadataResult) MilestoneToID(title string) (string, error) {
	for _, m := range m.Milestones {
		if strings.EqualFold(title, m.Title) {
			return m.ID, nil
		}
	}
	return "", errors.New("not found")
}

func (m *RepoMetadataResult) Merge(m2 *RepoMetadataResult) {
	if len(m2.AssignableUsers) > 0 || len(m.AssignableUsers) == 0 {
		m.AssignableUsers = m2.AssignableUsers
	}

	if len(m2.Teams) > 0 || len(m.Teams) == 0 {
		m.Teams = m2.Teams
	}

	if len(m2.Labels) > 0 || len(m.Labels) == 0 {
		m.Labels = m2.Labels
	}

	if len(m2.Projects) > 0 || len(m.Projects) == 0 {
		m.Projects = m2.Projects
	}

	if len(m2.Milestones) > 0 || len(m.Milestones) == 0 {
		m.Milestones = m2.Milestones
	}
}

type RepoMetadataInput struct {
	Assignees  bool
	Reviewers  bool
	Labels     bool
	Projects   bool
	Milestones bool
}

// RepoMetadata pre-fetches the metadata for attaching to issues and pull requests
func RepoMetadata(client *Client, repo ghrepo.Interface, input RepoMetadataInput) (*RepoMetadataResult, error) {
	result := RepoMetadataResult{}
	errc := make(chan error)
	count := 0

	if input.Assignees || input.Reviewers {
		count++
		go func() {
			users, err := RepoAssignableUsers(client, repo)
			if err != nil {
				err = fmt.Errorf("error fetching assignees: %w", err)
			}
			result.AssignableUsers = users
			errc <- err
		}()
	}
	if input.Reviewers {
		count++
		go func() {
			teams, err := OrganizationTeams(client, repo)
			// TODO: better detection of non-org repos
			if err != nil && !strings.HasPrefix(err.Error(), "Could not resolve to an Organization") {
				errc <- fmt.Errorf("error fetching organization teams: %w", err)
				return
			}
			result.Teams = teams
			errc <- nil
		}()
	}
	if input.Labels {
		count++
		go func() {
			labels, err := RepoLabels(client, repo)
			if err != nil {
				err = fmt.Errorf("error fetching labels: %w", err)
			}
			result.Labels = labels
			errc <- err
		}()
	}
	if input.Projects {
		count++
		go func() {
			projects, err := RepoAndOrgProjects(client, repo)
			if err != nil {
				errc <- err
				return
			}
			result.Projects = projects
			errc <- nil
		}()
	}
	if input.Milestones {
		count++
		go func() {
			milestones, err := RepoMilestones(client, repo, "open")
			if err != nil {
				err = fmt.Errorf("error fetching milestones: %w", err)
			}
			result.Milestones = milestones
			errc <- err
		}()
	}

	var err error
	for i := 0; i < count; i++ {
		if e := <-errc; e != nil {
			err = e
		}
	}

	return &result, err
}

type ResponseData struct {
	Search struct {
		RepositoryCount int
		Nodes           []TemplateRepository
	}
}

func QueryReposOnTopics(client *Client, repo ghrepo.Interface, topics []string) (*ResponseData, error) {
	query := `
	query QueryRepos($query: String!) {
		search(query: $query, type: REPOSITORY, first: 100) {
			repositoryCount
			nodes {
			  ... on Repository {
				nameWithOwner
				description
				isTemplate
				url
			  }
			}
		}
  }
	`
	const topicStr = "topic:"
	var topic string

	for i := 0; i < len(topics); i++ {
		topic = topic + topicStr + topics[i] + " "
	}

	variables := map[string]interface{}{
		"query": topic,
	}

	var response ResponseData

	err := client.GraphQL(repo.RepoHost(), query, variables, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

type Entries struct {
	Name   string
	Object struct {
		Text string
	}
}

type Edges struct {
	Node struct {
		Object struct {
			Entries []Entries
		}
	}
}

type FilesResponseData struct {
	Search struct {
		Edges []Edges
	}
}

func FetchFilesInARepo(client *Client, repo ghrepo.Interface, repoName string) (*FilesResponseData, error) {
	query := `
	query GetFilesQuery($query: String!) {
		search(first: 1, type: REPOSITORY, query: $query) {
		   edges {
			 node {
			   ... on Repository {
				 object(expression: "main:") {
				   ... on Tree {
					 entries {
					   name
					   object {
						 ... on Blob {
						   text
						 }
					   }
					 }
				   }
				 }
			   }
			 }
		   }
		 }
	   }
	`
	queryStr := "repo:" + repoName

	variables := map[string]interface{}{
		"query": queryStr,
	}

	var response FilesResponseData

	err := client.GraphQL(repo.RepoHost(), query, variables, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c Client) SendRequest(method string, url string, body io.Reader, accept string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", accept)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, HandleHTTPError(resp)
	}

	return resp, nil
}

func UpdateRepo(c *Client, baseRepo ghrepo.Interface, repoName string, variablesMap map[string]string) error {
	ref := "heads/main"
	commitMessage := "Patched values in templates"

	//get latest commit sha on heads/master, keep polling until there is a commit
	resp, err := c.SendRequest("GET", fmt.Sprintf("%srepos/%s/git/ref/%s",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, ref), nil, "application/vnd.github.v3+json")
	for err != nil {
		resp, err = c.SendRequest("GET", fmt.Sprintf("%srepos/%s/git/ref/%s",
			ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, ref), nil, "application/vnd.github.v3+json")
		time.Sleep(1 * time.Second)
	}
	fmt.Println(resp.StatusCode)
	var headRef map[string]interface{}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bodyBytes, &headRef)
	latestCommitSha := headRef["object"].(map[string]interface{})["sha"].(string)

	//get latest tree from commit sha
	resp, err = c.SendRequest("GET", fmt.Sprintf("%srepos/%s/git/commits/%s",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, latestCommitSha), nil, "application/vnd.github.v3+json")
	if err != nil {
		return err
	}
	var latestCommit map[string]interface{}
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	json.Unmarshal(bodyBytes, &latestCommit)
	latestTreeSha := latestCommit["tree"].(map[string]interface{})["sha"]

	//get latest tree
	resp, err = c.SendRequest("GET", fmt.Sprintf("%srepos/%s/git/trees/%s?recursive=true",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, latestTreeSha), nil, "application/vnd.github.v3+json")
	if err != nil {
		return err
	}
	var tree map[string]interface{}
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	json.Unmarshal(bodyBytes, &tree)
	originalFiles := tree["tree"]
	newFiles, err := GetUpdatedFiles(c, baseRepo, repoName, originalFiles, variablesMap)
	if err != nil {
		return err
	}
	var treeParams TreeParams
	treeParams.Blobs = newFiles
	treeParams.BaseTree = latestTreeSha.(string)
	treeParamsBytes, _ := json.Marshal(treeParams)
	treeParamsReader := bytes.NewReader(treeParamsBytes)
	resp, err = c.SendRequest("POST", fmt.Sprintf("%srepos/%s/git/trees",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName), treeParamsReader, "application/vnd.github.v3+json")
	if err != nil {
		return err
	}
	var newTree map[string]interface{}
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	json.Unmarshal(bodyBytes, &newTree)
	newTreeSha := newTree["sha"].(string)

	//create a commit with new tree
	var commitParams CommitParams
	commitParams.Message = commitMessage
	commitParams.TreeSha = newTreeSha
	commitParams.Parents = []string{latestCommitSha}
	commitParamsBytes, _ := json.Marshal(commitParams)
	commitParamsReader := bytes.NewReader(commitParamsBytes)
	resp, err = c.SendRequest("POST", fmt.Sprintf("%srepos/%s/git/commits",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName), commitParamsReader, "application/vnd.github.v3+json")
	if err != nil {
		return err
	}
	var newCommit map[string]interface{}
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	json.Unmarshal(bodyBytes, &newCommit)

	//update current ref
	newCommitSha := newCommit["sha"].(string)
	var refParams RefParams
	refParams.CommitSha = newCommitSha
	refParamsBytes, _ := json.Marshal(refParams)
	refParamsReader := bytes.NewReader(refParamsBytes)
	resp, err = c.SendRequest("PATCH", fmt.Sprintf("%srepos/%s/git/refs/%s",
		ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, ref), refParamsReader, "application/vnd.github.v3+json")
	if err != nil {
		return err
	}

	return nil
}

func GetUpdatedFiles(c *Client, baseRepo ghrepo.Interface, repoName string, files interface{}, variablesMap map[string]string) ([]Blobs, error) {
	fmt.Println("Patching the values in templates")
	var newFiles []Blobs
	filesArray := files.([]interface{})
	acceleratorFilePath := "accelerator.json"
	reg, _ := regexp.Compile("\\${{\\s*acc\\.(\\w+)\\s*}}")
	for _, value := range filesArray {
		file := value.(map[string]interface{})
		filePath := file["path"].(string)
		fileMode := file["mode"].(string)
		fileType := file["type"].(string)

		if fileType == "blob" && filePath != acceleratorFilePath {

			fileSha := file["sha"]

			resp, err := c.SendRequest("GET", fmt.Sprintf("%srepos/%s/git/blobs/%s",
				ghinstance.RESTPrefix(baseRepo.RepoHost()), repoName, fileSha), nil, "application/vnd.github.v3+json")
			if err != nil {
				return nil, err
			}
			var fileContent map[string]interface{}
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			json.Unmarshal(bodyBytes, &fileContent)
			byteArray, err := base64.StdEncoding.DecodeString(fileContent["content"].(string))
			if err != nil {
				return nil, err
			}
			contentString := string(byteArray)
			newContentString := reg.ReplaceAllStringFunc(contentString, func(s string) string {
				key := reg.FindStringSubmatch(s)[1]
				if val, isPresent := variablesMap[key]; isPresent {
					return val
				}
				return s
			})
			// newContentString := reg.ReplaceAllString(contentString, GetValueFor("$1"))
			var newFile Blobs
			newFile.FilePath = filePath
			newFile.FileMode = fileMode
			newFile.FileType = fileType
			newFile.FileContent = newContentString

			newFiles = append(newFiles, newFile)
		}
	}

	return newFiles, nil
}

func GetValueFor(key string) string {
	fmt.Println(key)
	return key
}

type RefParams struct {
	CommitSha string `json:"sha"`
}

type CommitParams struct {
	Message string   `json:"message"`
	TreeSha string   `json:"tree"`
	Parents []string `json:"parents"`
}

type TreeParams struct {
	Blobs    []Blobs `json:"tree"`
	BaseTree string  `json:"base_tree"`
}

type Blobs struct {
	FilePath    string `json:"path"`
	FileMode    string `json:"mode"`
	FileType    string `json:"type"`
	FileContent string `json:"content"`
}

type RepoResolveInput struct {
	Assignees  []string
	Reviewers  []string
	Labels     []string
	Projects   []string
	Milestones []string
}

// RepoResolveMetadataIDs looks up GraphQL node IDs in bulk
func RepoResolveMetadataIDs(client *Client, repo ghrepo.Interface, input RepoResolveInput) (*RepoMetadataResult, error) {
	users := input.Assignees
	hasUser := func(target string) bool {
		for _, u := range users {
			if strings.EqualFold(u, target) {
				return true
			}
		}
		return false
	}

	var teams []string
	for _, r := range input.Reviewers {
		if i := strings.IndexRune(r, '/'); i > -1 {
			teams = append(teams, r[i+1:])
		} else if !hasUser(r) {
			users = append(users, r)
		}
	}

	// there is no way to look up projects nor milestones by name, so preload them all
	mi := RepoMetadataInput{
		Projects:   len(input.Projects) > 0,
		Milestones: len(input.Milestones) > 0,
	}
	result, err := RepoMetadata(client, repo, mi)
	if err != nil {
		return result, err
	}
	if len(users) == 0 && len(teams) == 0 && len(input.Labels) == 0 {
		return result, nil
	}

	query := &bytes.Buffer{}
	fmt.Fprint(query, "query RepositoryResolveMetadataIDs {\n")
	for i, u := range users {
		fmt.Fprintf(query, "u%03d: user(login:%q){id,login}\n", i, u)
	}
	if len(input.Labels) > 0 {
		fmt.Fprintf(query, "repository(owner:%q,name:%q){\n", repo.RepoOwner(), repo.RepoName())
		for i, l := range input.Labels {
			fmt.Fprintf(query, "l%03d: label(name:%q){id,name}\n", i, l)
		}
		fmt.Fprint(query, "}\n")
	}
	if len(teams) > 0 {
		fmt.Fprintf(query, "organization(login:%q){\n", repo.RepoOwner())
		for i, t := range teams {
			fmt.Fprintf(query, "t%03d: team(slug:%q){id,slug}\n", i, t)
		}
		fmt.Fprint(query, "}\n")
	}
	fmt.Fprint(query, "}\n")

	response := make(map[string]json.RawMessage)
	err = client.GraphQL(repo.RepoHost(), query.String(), nil, &response)
	if err != nil {
		return result, err
	}

	for key, v := range response {
		switch key {
		case "repository":
			repoResponse := make(map[string]RepoLabel)
			err := json.Unmarshal(v, &repoResponse)
			if err != nil {
				return result, err
			}
			for _, l := range repoResponse {
				result.Labels = append(result.Labels, l)
			}
		case "organization":
			orgResponse := make(map[string]OrgTeam)
			err := json.Unmarshal(v, &orgResponse)
			if err != nil {
				return result, err
			}
			for _, t := range orgResponse {
				result.Teams = append(result.Teams, t)
			}
		default:
			user := RepoAssignee{}
			err := json.Unmarshal(v, &user)
			if err != nil {
				return result, err
			}
			result.AssignableUsers = append(result.AssignableUsers, user)
		}
	}

	return result, nil
}

type RepoProject struct {
	ID           string
	Name         string
	ResourcePath string
}

// RepoProjects fetches all open projects for a repository
func RepoProjects(client *Client, repo ghrepo.Interface) ([]RepoProject, error) {
	type responseData struct {
		Repository struct {
			Projects struct {
				Nodes    []RepoProject
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			} `graphql:"projects(states: [OPEN], first: 100, orderBy: {field: NAME, direction: ASC}, after: $endCursor)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner":     githubv4.String(repo.RepoOwner()),
		"name":      githubv4.String(repo.RepoName()),
		"endCursor": (*githubv4.String)(nil),
	}

	gql := graphQLClient(client.http, repo.RepoHost())

	var projects []RepoProject
	for {
		var query responseData
		err := gql.QueryNamed(context.Background(), "RepositoryProjectList", &query, variables)
		if err != nil {
			return nil, err
		}

		projects = append(projects, query.Repository.Projects.Nodes...)
		if !query.Repository.Projects.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Repository.Projects.PageInfo.EndCursor)
	}

	return projects, nil
}

// RepoAndOrgProjects fetches all open projects for a repository and its org
func RepoAndOrgProjects(client *Client, repo ghrepo.Interface) ([]RepoProject, error) {
	projects, err := RepoProjects(client, repo)
	if err != nil {
		return projects, fmt.Errorf("error fetching projects: %w", err)
	}

	orgProjects, err := OrganizationProjects(client, repo)
	// TODO: better detection of non-org repos
	if err != nil && !strings.HasPrefix(err.Error(), "Could not resolve to an Organization") {
		return projects, fmt.Errorf("error fetching organization projects: %w", err)
	}
	projects = append(projects, orgProjects...)

	return projects, nil
}

type RepoAssignee struct {
	ID    string
	Login string
}

// RepoAssignableUsers fetches all the assignable users for a repository
func RepoAssignableUsers(client *Client, repo ghrepo.Interface) ([]RepoAssignee, error) {
	type responseData struct {
		Repository struct {
			AssignableUsers struct {
				Nodes    []RepoAssignee
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			} `graphql:"assignableUsers(first: 100, after: $endCursor)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner":     githubv4.String(repo.RepoOwner()),
		"name":      githubv4.String(repo.RepoName()),
		"endCursor": (*githubv4.String)(nil),
	}

	gql := graphQLClient(client.http, repo.RepoHost())

	var users []RepoAssignee
	for {
		var query responseData
		err := gql.QueryNamed(context.Background(), "RepositoryAssignableUsers", &query, variables)
		if err != nil {
			return nil, err
		}

		users = append(users, query.Repository.AssignableUsers.Nodes...)
		if !query.Repository.AssignableUsers.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Repository.AssignableUsers.PageInfo.EndCursor)
	}

	return users, nil
}

type RepoLabel struct {
	ID   string
	Name string
}

// RepoLabels fetches all the labels in a repository
func RepoLabels(client *Client, repo ghrepo.Interface) ([]RepoLabel, error) {
	type responseData struct {
		Repository struct {
			Labels struct {
				Nodes    []RepoLabel
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			} `graphql:"labels(first: 100, orderBy: {field: NAME, direction: ASC}, after: $endCursor)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner":     githubv4.String(repo.RepoOwner()),
		"name":      githubv4.String(repo.RepoName()),
		"endCursor": (*githubv4.String)(nil),
	}

	gql := graphQLClient(client.http, repo.RepoHost())

	var labels []RepoLabel
	for {
		var query responseData
		err := gql.QueryNamed(context.Background(), "RepositoryLabelList", &query, variables)
		if err != nil {
			return nil, err
		}

		labels = append(labels, query.Repository.Labels.Nodes...)
		if !query.Repository.Labels.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Repository.Labels.PageInfo.EndCursor)
	}

	return labels, nil
}

type RepoMilestone struct {
	ID    string
	Title string
}

// RepoMilestones fetches milestones in a repository
func RepoMilestones(client *Client, repo ghrepo.Interface, state string) ([]RepoMilestone, error) {
	type responseData struct {
		Repository struct {
			Milestones struct {
				Nodes    []RepoMilestone
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			} `graphql:"milestones(states: $states, first: 100, after: $endCursor)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	var states []githubv4.MilestoneState
	switch state {
	case "open":
		states = []githubv4.MilestoneState{"OPEN"}
	case "closed":
		states = []githubv4.MilestoneState{"CLOSED"}
	case "all":
		states = []githubv4.MilestoneState{"OPEN", "CLOSED"}
	default:
		return nil, fmt.Errorf("invalid state: %s", state)
	}

	variables := map[string]interface{}{
		"owner":     githubv4.String(repo.RepoOwner()),
		"name":      githubv4.String(repo.RepoName()),
		"states":    states,
		"endCursor": (*githubv4.String)(nil),
	}

	gql := graphQLClient(client.http, repo.RepoHost())

	var milestones []RepoMilestone
	for {
		var query responseData
		err := gql.QueryNamed(context.Background(), "RepositoryMilestoneList", &query, variables)
		if err != nil {
			return nil, err
		}

		milestones = append(milestones, query.Repository.Milestones.Nodes...)
		if !query.Repository.Milestones.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Repository.Milestones.PageInfo.EndCursor)
	}

	return milestones, nil
}

func MilestoneByTitle(client *Client, repo ghrepo.Interface, state, title string) (*RepoMilestone, error) {
	milestones, err := RepoMilestones(client, repo, state)
	if err != nil {
		return nil, err
	}

	for i := range milestones {
		if strings.EqualFold(milestones[i].Title, title) {
			return &milestones[i], nil
		}
	}
	return nil, fmt.Errorf("no milestone found with title %q", title)
}

func MilestoneByNumber(client *Client, repo ghrepo.Interface, number int32) (*RepoMilestone, error) {
	var query struct {
		Repository struct {
			Milestone *RepoMilestone `graphql:"milestone(number: $number)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner":  githubv4.String(repo.RepoOwner()),
		"name":   githubv4.String(repo.RepoName()),
		"number": githubv4.Int(number),
	}

	gql := graphQLClient(client.http, repo.RepoHost())

	err := gql.QueryNamed(context.Background(), "RepositoryMilestoneByNumber", &query, variables)
	if err != nil {
		return nil, err
	}
	if query.Repository.Milestone == nil {
		return nil, fmt.Errorf("no milestone found with number '%d'", number)
	}

	return query.Repository.Milestone, nil
}

func ProjectNamesToPaths(client *Client, repo ghrepo.Interface, projectNames []string) ([]string, error) {
	var paths []string
	projects, err := RepoAndOrgProjects(client, repo)
	if err != nil {
		return paths, err
	}
	return ProjectsToPaths(projects, projectNames)
}
