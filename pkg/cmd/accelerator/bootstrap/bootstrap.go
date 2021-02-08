package bootstrap

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/api"
	"github.com/cli/cli/internal/ghrepo"
	"github.com/cli/cli/pkg/cmd/repo/create"
	"github.com/cli/cli/pkg/cmd/secret/set"
	"github.com/cli/cli/pkg/cmdutil"
	"github.com/cli/cli/pkg/prompt"
	"github.com/spf13/cobra"
)

type BootstrapOptions struct {
	HttpClient func() (*http.Client, error)
	BaseRepo   func() (ghrepo.Interface, error)
}

type Vars struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type EnvVars struct {
	ActionPath string `json:"actionPath"`
	Variables  []Vars `json:"variables"`
}

type Accelerator struct {
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	EnvironmentVariables []EnvVars `json:"environmentVariables`
	Secrets              []Vars    `json:"secrets"`
}

type Inputs struct {
	Name  string
	Value string
}

func NewCmdBootstrap(f *cmdutil.Factory, runF func(*BootstrapOptions) error) *cobra.Command {
	opts := &BootstrapOptions{
		HttpClient: f.HttpClient,
	}

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Args:  cobra.ExactArgs(0),
		Short: "Bootstrap applications",
		Long: heredoc.Docf(`
			Bootstrap applications with a starter repo
		`, "`"),
		Example: heredoc.Doc(`
			# start interactive setup
			$ gh accelerator bootstrap
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.BaseRepo = f.BaseRepo

			return bootstrapRun(opts, f)
		},
	}

	return cmd
}

func bootstrapRun(opts *BootstrapOptions, f *cmdutil.Factory) error {
	languages := make([]string, 0)
	providers := make([]string, 0)
	targets := make([]string, 0)

	languages = append(languages, "Nodejs")
	languages = append(languages, "ASP.NET")
	languages = append(languages, "Java")

	providers = append(providers, "Azure")
	providers = append(providers, "AWS")
	providers = append(providers, "Google")

	targets = append(targets, "Kubernetes")
	targets = append(targets, "Function App")
	targets = append(targets, "Web App")

	var provider int
	var language int
	var target int
	var repoSelection int

	prompt.SurveyAskOne(&survey.Select{
		Message: "Choose your language",
		Options: languages,
	}, &language)

	prompt.SurveyAskOne(&survey.Select{
		Message: "Choose your cloud provider",
		Options: providers,
	}, &provider)

	prompt.SurveyAskOne(&survey.Select{
		Message: "Choose your deployment target",
		Options: targets,
	}, &target)

	repos, err := fetchRepos(toLowercaseAndRemoveWhiteSpace(languages[language]),
		toLowercaseAndRemoveWhiteSpace(providers[provider]),
		toLowercaseAndRemoveWhiteSpace(targets[target]),
		opts)

	if err != nil {
		return err
	}

	fmt.Println("Found", repos.Search.RepositoryCount, "template repositories matching your specifications")

	repositoryOptions := make([]string, 0)

	for i := 0; i < repos.Search.RepositoryCount; i++ {
		repositoryOptions = append(repositoryOptions, repos.Search.Nodes[i].NameWithOwner+" "+repos.Search.Nodes[i].Url)
	}

	prompt.SurveyAskOne(&survey.Select{
		Message: "Choose any template repository to get started",
		Options: repositoryOptions,
	}, &repoSelection)

	chosenRepoDetail := strings.Split(repositoryOptions[repoSelection], " ")

	accelerator, err := getAcceleratorFileContents(chosenRepoDetail[0], opts)

	if err != nil {
		return err
	}

	inputSecrets, err := getInputDetails(accelerator.Secrets, true)

	if err != nil {
		return err
	}

	inputVariables, err := getInputDetails(accelerator.EnvironmentVariables, false)

	if err != nil {
		return err
	}

	repoName, repoDescription, err := getNewRepoDetails()

	if err != nil {
		return err
	}

	repoInputOptions := create.CreateOptions{
		HttpClient: f.HttpClient,
		Config:     f.Config,
		IO:         f.IOStreams,

		Name:          repoName,
		Description:   repoDescription,
		Public:        true,
		Template:      chosenRepoDetail[0],
		ConfirmSubmit: true,
		IsAccelerator: true,
	}

	fmt.Printf("Generating a new repository %s based on the template %s", repoName, chosenRepoDetail[0])

	err = create.CreateRun(&repoInputOptions)
	if err != nil {
		return err
	}

	for i := 0; i < len(inputSecrets); i++ {
		secretCreateOptions := set.SetOptions{
			HttpClient: f.HttpClient,
			IO:         f.IOStreams,
			BaseRepo: func() (ghrepo.Interface, error) {
				return ghrepo.FromFullName(repoName)
			},

			SecretName: inputSecrets[i].Name,
			Body:       inputSecrets[i].Value,
		}

		err = set.SetRun(&secretCreateOptions)
		if err != nil {
			return err
		}
	}

	return nil
}

func fetchRepos(language string, provider string, target string, opts *BootstrapOptions) (*api.ResponseData, error) {
	httpClient, err := opts.HttpClient()
	if err != nil {
		return nil, err
	}
	apiClient := api.NewClientFromHTTP(httpClient)

	baseRepo, err := opts.BaseRepo()
	if err != nil {
		return nil, err
	}

	var repos *api.ResponseData

	repos, err = api.QueryReposOnTopics(apiClient, baseRepo, []string{language, provider, target})

	if err != nil {
		return nil, err
	}

	return repos, nil
}

func getAcceleratorFileContents(baseTemplateRepo string, opts *BootstrapOptions) (*Accelerator, error) {
	httpClient, err := opts.HttpClient()
	if err != nil {
		return nil, err
	}
	apiClient := api.NewClientFromHTTP(httpClient)

	baseRepo, err := opts.BaseRepo()
	if err != nil {
		return nil, err
	}

	fileResponse, err := api.FetchFilesInARepo(apiClient, baseRepo, "Sample-Ganes-Org/Nodejs-On-Azure-Accelerator")

	if err != nil {
		return nil, err
	}

	// Get Accelerator file contents

	const acceleratorFileName = "accelerator.json"
	var acceleratorFileContent string

	for i := 0; i < len(fileResponse.Search.Edges); i++ {
		entries := fileResponse.Search.Edges[i].Node.Object.Entries
		for j := 0; j < len(entries); j++ {
			if strings.Compare(acceleratorFileName, entries[j].Name) == 0 {
				acceleratorFileContent = entries[j].Object.Text
				break
			}
		}
		if len(acceleratorFileContent) > 0 {
			break
		}
	}

	var accelerator Accelerator
	json.Unmarshal([]byte(acceleratorFileContent), &accelerator)

	// fileContents, err := apiClient.GetFileContents(baseRepo, "Ganeshrockz/AnotherTest", ".github/workflows/manage-azure-policy-140c7e03.yml")

	// if err != nil {
	// 	return err
	// }

	// defer fileContents.Close()

	//parsedFileResponse, err := getFileContentsResponse(fileContents)

	// if err != nil {
	// 	return err
	// }

	// fmt.Println(parsedFileResponse)

	return &accelerator, nil
}

func toLowercaseAndRemoveWhiteSpace(str string) string {
	return strings.ReplaceAll(strings.ToLower(str), " ", "")
}

func getInputDetails(inputs []Vars, isPasswordInput bool) ([]Inputs, error) {
	userInputValues := make([]Inputs, 0)
	for i := 0; i < len(inputs); i++ {
		var input string
		var err error

		if isPasswordInput {
			err = prompt.SurveyAskOne(&survey.Password{
				Message: "Enter Value for Secret " + inputs[i].Name,
			}, &input, survey.WithValidator(survey.Required))
		} else {
			err = prompt.SurveyAskOne(&survey.Input{
				Message: "Enter value for variable " + inputs[i].Name,
			}, &input)
		}

		if err != nil {
			return nil, err
		}

		userInputValues = append(userInputValues, Inputs{Name: inputs[i].Name, Value: input})
	}

	return userInputValues, nil
}

func getNewRepoDetails() (string, string, error) {
	qs := []*survey.Question{}

	orgNameQuestion := &survey.Question{
		Name: "orgName",
		Prompt: &survey.Input{
			Message: "Organization name",
		},
	}
	qs = append(qs, orgNameQuestion)

	repoNameQuestion := &survey.Question{
		Name: "repoName",
		Prompt: &survey.Input{
			Message: "Repository name",
		},
	}
	qs = append(qs, repoNameQuestion)

	repoDescriptionQuestion := &survey.Question{
		Name: "repoDescription",
		Prompt: &survey.Input{
			Message: "Repository Description",
		},
	}
	qs = append(qs, repoDescriptionQuestion)

	answers := struct {
		OrgName         string
		RepoName        string
		RepoDescription string
	}{}

	err := prompt.SurveyAsk(qs, &answers)

	if err != nil {
		return "", "", err
	}

	return answers.OrgName + "/" + answers.RepoName, answers.RepoDescription, nil
}

func getFileContentsResponse(fileContents io.Reader) (string, error) {
	const contentKey = "content"

	contents := bufio.NewScanner(fileContents)
	var content string
	for contents.Scan() {
		content = contents.Text()
		break
	}

	splitContent := strings.Split(content, ",")

	for i := range splitContent {
		if strings.Contains(splitContent[i], "\"content\"") {
			fmt.Println(strings.ReplaceAll(strings.Split(splitContent[i], ":")[1], "\"", ""))
			decodedContent, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.Split(splitContent[i], ":")[1], "\"", ""))
			if err != nil {
				fmt.Println("CONTENT ", err)
				return "", err
			}

			content = string(decodedContent)

			fmt.Println("CONTENT ", content)

			break
		}
	}

	return content, nil
}
