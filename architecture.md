# Baseline Assessment Architecture

An Assessment is the result of evaluating multiple compliance controls against various sources of data and drawing conclusions based on that data.

## Input evidence data and sources

The scanner relies on various sources and forms of input data to assess the controls. Examples include:
  * Source: GitHub/GitLab
    - Input: GitHub/GitLab API (REST and/or GraphQL) responses
    - Forms: JSON
  * Source: git repository
    - Input: any/all VCS data of interest
    - Forms: file contents, commit history, etc.
  * Source: Security Insights data
    - Input: file contents
    - Forms: JSON, YAML, cue, etc.
  * Source: SAST tools like actionlint, semgrep, etc.
    - Input: whatever useful output produced by the tool(s)
    - Forms: native language types via SDKs and JSON interchange

## Desirable qualities of the data layer

### Separate the data structures from the data sources

This allows for better separation of concerns and better suits the ways the checks will need to be run in order to comprehensively test them, but also to account for the following example use cases:

 * I want to run an assessment in a GitHub Actions workflow where I have the git repository available on disk on the host running the assessment and therefore I want to provide that git repository data as direct input to the assessment.
 * I want to run an assesment to determine how many baseline controls can be satisfied given a certain SecurityInsights input. This feels useful for both testing purposes, but also for educating maintainers on the use of Insights data to satisfy the controls.
 * I want to run an assessment as a CLI tool and I expect it to source whatever data it can based on simple user provided input: a unique repository identifier within a given forge and an API token for that forge that provides the necessary AuthN/AuthZ.

### Design and plan for additional types and sources of input data

The group has discussed the following additional types and sources of input data:

 * SBOMs
 * Attestations
 * Container images
 * Binaries and other released artifact files

As we consider adding support for these, ensure we separate the concerns of how the data is obtained from how its structured, stored and processed.

### Keep reference data separate from input and output data

The baseline and insights specifications are examples of key reference data that the assessment architecture should treat as versioned and immutable. The assessment application should reference this data whenever/wherever possible rather than duplicate it in manually maintained source code.

### Input evidence data from multiple sources may duplicate and/or make conflicting assertions

Some instructive examples are:

 * The GitHub API provides a code of conduct URL and file contents and the Insights data provides a different code of conduct URL, which, when fetched, has contents that differ from those provided by GitHub.
 * The GitHub API provides evidence that private vulnerability reporting is configured on the project's primary repository, but the Insights data claims that vulnerability reports are not supported by the project.

### Input evidence data has differing level of trust, quality and specificity

Consider an evaluation of control "OSPS-AC-03.01 When a direct commit is attempted on the project's primary branch, an enforcement mechanism MUST prevent the change from being applied." and how it might evaluate differing levels of quality and specificity of input evidence data.

If the input data only includes GitHub API provided branch protection rules for the primary branch but does not include GitHub API rulesets for the primary branch, the evaluation logic is dealing with both incomplete data, but also is forced to evaluate the rule syntax and configuration to attempt to understand the effect of the configuration data on the ability to commit directly to the primary branch.

If however, the input data above is combined with positive results of a synthetic check where the evaluation logic attempts to apply a direct commit to the primary branch and exercises this test with every role granted in the repository, observing that each attempt is denied we now have both medium and high quality data upon which we can draw conclusions.

Discussion points that follow from this observation:
 * Should assessment results include some notion of data quality or confidence rating in the conclusions drawn from the data?
 * In examples like the one above, should the evaluation logic report a single conclusion based on combining the disparate inputs and sources of data or should the conclusions be reported separately, thereby allowing/expecting the data consumer to draw their own conclusions?
 * How should we think about communicating the level of trust we have in the input data sources? Should the assessment results imply equal or differing levels of trusts and how that should trust be substantiated?

## Control evaluation and assessment data output in the face of multiple sources and types of evidence

When a baseline control can be evaluated with multiple sources, types of input evidence, the evaluation logic and the results data it emits should be as detailed in possible and identify the specific source and type of evidence that supports the result and ideally provide an immutable snapshot of the evidence that was used to draw the conclusion.

I think this leaves us with the following types and relationships in the assessment output

 * Control requirements have 1 or more assessment methods or strategies.
 * Each method/strategy contains properties that indicate:
   * Was it run?
   * List of 1 or more data inputs analyzed and what was the source and trust of each input dataset?
   * What conclusion was reached? Pass/Fail/Needs Review/Error
   * List of 1 or more evidence objects that support the conclusion


How that output might look for an artificially complex evaluation of the OSPS-AC-03 control

```yaml
evaluations: # list of controls that were evaluated
  - name: "OSPS Baseline Controls Evaluation"
    controlID: "OSPS-AC-03"
    assessments:
      - requirementID: "OSPS-AC-03.01"
        methods:
          - name: "GitHub Enforcement mechanism configuration check"
            description: "Evaluate the GitHub API-provided configuration data for the repository's branch protection rules and rulesets for the repository's primary branch"
            run: true
            result: passed
            confidence: Medium
            inputs:
                - type: API
                  source: automated
                  location: https://api.github.com/repos/OWNER/REPO/rules/branches/BRANCH
                - type: API
                  source: automated
                  location: https://api.github.com/repos/OWNER/REPO/branches/BRANCH/protection
            evidence:
                - type: API
                  source: automated
                  resource: file location to logged http request and response specifics for first input
                  input_reference: https://api.github.com/repos/OWNER/REPO/rules/branches/BRANCH
                - type: API
                  source: automated
                  resource: file location to logged http request and response specifics for second input
                  input_reference: https://api.github.com/repos/OWNER/REPO/branches/BRANCH/protection
            
                
          - name: "Primary branch push check"
            description: "Attempt to push commits directly to the primary branch, making one attempt for each repository role configured"
            run: true
            result: passed
            confidence: High
            inputs:
                - type: Configuration
                  source: user-provided
                  location: vars.primary_branch_check_identities # reference the user-provided configuration data powering the synthetic test
                - type: SyntheticExecutionResults
                  source: automated
                  location: https://documentation_page_for_synthetic_test
            evidence:
                - type: SyntheticExecutionResults
                  source: automated
                  resource: file location to logged test execution
                  input_reference: https://documentation_page_for_synthetic_test
```
