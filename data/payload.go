package data

import (
	"context"
	"fmt"

	"github.com/google/go-github/v71/github"
	si "github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type Payload struct {
	*GraphqlRepoData
	*RestData
	Config             *config.Config
	SuspectedBinaries  []string
	SecurityInsights   si.SecurityInsights
	RepositoryMetadata RepositoryMetadata
}

type RepositoryMetadata interface {
	IsActive() bool
	IsPublic() bool
	IsMFARequiredForAdministrativeActions() bool
	UnableToEvaluateMFARequirement() bool
}

type RepositoryContents interface {
	GetWorkflows() []Workflow
	GetFile(path string) ([]byte, error)
}

type GitHubRepositoryMetadata struct {
	Releases                       []ReleaseData
	Rulesets                       []Ruleset
	ghRepo                         *github.Repository
	ghOrg                          *github.Organization
	unableToEvaluateMFARequirement bool
}

func (r *GitHubRepositoryMetadata) IsActive() bool {
	return !r.ghRepo.GetArchived() && !r.ghRepo.GetDisabled()
}

func (r *GitHubRepositoryMetadata) IsPublic() bool {
	return !r.ghRepo.GetPrivate()
}

func (r *GitHubRepositoryMetadata) IsMFARequiredForAdministrativeActions() bool {
	return r.ghOrg.GetTwoFactorRequirementEnabled()
}

func (r *GitHubRepositoryMetadata) UnableToEvaluateMFARequirement() bool {
	return r.unableToEvaluateMFARequirement
}

type ReleaseData struct {
	Id      int            `json:"id"`
	Name    string         `json:"name"`
	TagName string         `json:"tag_name"`
	URL     string         `json:"url"`
	Assets  []ReleaseAsset `json:"assets"`
}

type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

type Ruleset struct {
	Type       string `json:"type"`
	Parameters struct {
		RequiredChecks []struct {
			Context string `json:"context"`
		} `json:"required_status_checks"`
	} `json:"parameters"`
}

type BranchProtectionRule struct {
}

func Loader(config *config.Config) (payload interface{}, err error) {
	graphql, client, err := getGraphqlRepoData(config)
	if err != nil {
		return nil, err
	}

	suspectedBinaries, err := getSuspectedBinaries(client, config, graphql.Repository.DefaultBranchRef.Name)
	if err != nil {
		return nil, err
	}

	rest, err := getRestData(config)
	if err != nil {
		return nil, err
	}

	repositoryMetadata, err := loadRepositoryMetadata(config)
	if err != nil {
		return nil, err
	}

	return interface{}(Payload{
		GraphqlRepoData:    graphql,
		RestData:           rest,
		Config:             config,
		SuspectedBinaries:  suspectedBinaries,
		RepositoryMetadata: repositoryMetadata,
	}), nil
}

func loadSecurityInsights(config *config.Config) (data si.SecurityInsights, err error) {
	return si.SecurityInsights{}, nil
}

func loadRepositoryMetadata(config *config.Config) (data RepositoryMetadata, err error) {
	client := github.NewClient(nil).WithAuthToken(config.GetString("token"))
	repository, _, err := client.Repositories.Get(context.Background(), config.GetString("owner"), config.GetString("repo"))
	if err != nil {
		return &GitHubRepositoryMetadata{}, err
	}
	organization, _, err := client.Organizations.Get(context.Background(), config.GetString("owner"))
	if err != nil {
		config.Logger.Debug(fmt.Sprintf("Error querying GitHub REST API for the Organization details: %s", err.Error()))
		return &GitHubRepositoryMetadata{
			ghRepo:                         repository,
			unableToEvaluateMFARequirement: true,
		}, nil
	}
	return &GitHubRepositoryMetadata{
		ghRepo: repository,
		ghOrg:  organization,
	}, nil
}

func getGraphqlRepoData(config *config.Config) (data *GraphqlRepoData, client *githubv4.Client, err error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.GetString("token")},
	)
	httpClient := oauth2.NewClient(context.Background(), src)
	client = githubv4.NewClient(httpClient)

	variables := map[string]interface{}{
		"owner": githubv4.String(config.GetString("owner")),
		"name":  githubv4.String(config.GetString("repo")),
	}

	err = client.Query(context.Background(), &data, variables)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("Error querying GitHub GraphQL API: %s", err.Error()))
	}
	return data, client, err
}

func getRestData(config *config.Config) (data *RestData, err error) {
	r := &RestData{
		Config: config,
	}
	return r, r.Setup()
}
