# Contributing guide

This guide serves as a checklist before contributing to this repository. It mainly focuses on the steps to follow to submit an issue or a pull-request.

## 1. Issues

### 1.1 Before opening an issue

Please check the following points before posting an issue:
* Make sure you are using the latest commit (major releases are tagged, but corrections are available as new commits).
* Make sure your issue is a question/feedback/suggestions **related to** the software provided in this repository. Otherwise, please refer to section [3](CONTRIBUTING.md#3-support-requests-and-questions) below.
* Make sure your issue is not already reported/fixed on GitHub or discussed on a previous issue. Do not forget to browse into the **closed** issues.

### 1.2 Posting the issue

When you have checked the previous points, create a new report from the **Issues** tab of this repository. A template is available [here](../../issues/new/choose) to help you report the issue you are facing or the enhancement you would like to propose.

## 2. Pull Requests

### 2.1 Before opening a pull-request

STMicrolectronics is happy to receive contributions from the community, based on an initial Contributor License Agreement (CLA) procedure.

* If you are an individual writing original source code and you are sure **you own the intellectual property**, then you need to sign an Individual [CLA](https://cla.st.com).
* If you work for a company that wants also to allow you to contribute with your work, your company needs to provide a Corporate [CLA](https://cla.st.com) mentioning your GitHub account name.
* If you are not sure that a CLA (Individual or Corporate) has been signed for your GitHub account you can check the [CLA](https://cla.st.com) dedicated page.

Please note that:
* The Corporate CLA will always take precedence over the Individual CLA.
* One CLA submission is sufficient, for any project proposed by STMicroelectronics.

### 2.2 How to proceed

* We recommend to engage first a communication thru an issue, in order to present your proposal, just to confirm that it corresponds to STMicroelectronics' domain or scope.
* Then fork the project to your GitHub account to further develop your contribution. Please use the latest commit version.
* Please, submit one pull-request per new feature or proposal. This will ease the analysis and the final merge if accepted.

## 3. Support requests and questions

For support requests or any other question related to the product, the tools, the environment, you can submit a post to the **ST Community** on the appropriate topic [page](https://community.st.com/s/topiccatalog).

## 4. Commit message guidelines

To keep a clear and searchable history, format commit messages as:

```text
[type] [layer] short summary
```

### 4.1. Commit [Type]
The type describes the nature of the change:

- [refactor] : Internal code changes (structure, readability, performance) that may cause API/platform changes
- [fix] : Bug fix with no intentional API or platform behavior change
- [feat] : New functionality with no intentional API or platform behavior change
- [docs] : Documentation-only changes

If a change both adds a new feature and fixes a bug, choose the primary intent (usually feat).

### 4.2. Commit [Layer]
The layer indicates which part(s) of the codebase are impacted. Use one or more, separated by /:

- [all] : Large cross-cutting change
- [api] : API layer change
- [services] : Service layer chage 
- [core] : Core components or abstraction layers
- [certificate] : Certificate parsing / handling

### 4.3. Commit Short summary
The short summary should:
- Be in imperative present tense (e.g. add, fix, update, remove)
- Start with a lowercase verb
- Have no trailing period
- Be ≤ 72 characters
- Optionally reference an issue at the end using #<number>

### 4.4. Commit Body (optional but recommended)
Use the body when:

- The summary alone is not enough, or
- The change is complex, or
- You are introducing a behavior change, or
- The summary would exceed 72 characters.

Body guidelines:

Explain the motivation and why the change was needed. Describe the behavior before vs after
Mention breaking changes, side effects, or migration steps
Wrap lines at ~72–80 characters


### 4.5. Commit Examples 

| example                            | Notes                                |
|------------------------------------|--------------------------------------|
| `[fix] [api] implement null pointer check in api` | Bug fix in API layer                 |
| `[feat] [api/services] add stsafe-a120 derive key support `| New feature touching multiple layers |
| `[refactor] [core] rework cryptographic platfroms initialization `  | Internal rework, possible API impact |
| `[docs] [services] rework stsafe-a aes services documentation`  | Documentation-only change |

