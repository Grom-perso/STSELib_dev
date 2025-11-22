# Contributing guide

This guide serves as a checklist before contributing to this repository. It mainly focuses on the steps to follow to submit an issue or a pull-request.

## 1. Issues

### 1.1 Before opening an issue

Please check the following points before posting an issue:
* Make sure you are using the latest commit (major releases are tagged, but corrections are available as new commits).
* Make sure your issue is a question/feedback/suggestions **related to** the software provided in this repository. Otherwise, please refer to section [3](CONTRIBUTING.md#3-support-requests-and-questions) below.
* Make sure your issue is not already reported/fixed on GitHub or discussed on a previous issue. Do not forget to browse into the **closed** issues.

### 1.2 Posting the Issue

When you have checked the previous points, create a new report from the **Issues** tab of this repository. A template is available [here](../../issues/new/choose) to help you report the issue you are facing or the enhancement you would like to propose.

#### What to Include in Your Issue
- **Clear description**: Explain the problem or enhancement in detail
- **Steps to reproduce**: For bugs, provide clear reproduction steps
- **Expected vs. actual behavior**: Describe what should happen and what actually happens
- **Environment details**: Include platform, compiler, library version, etc.
- **Code snippets**: Provide minimal reproducible code examples if applicable

## 2. Pull Requests

### 2.1 Before opening a pull-request

STMicrolectronics is happy to receive contributions from the community, based on an initial Contributor License Agreement (CLA) procedure.

* If you are an individual writing original source code and you are sure **you own the intellectual property**, then you need to sign an Individual [CLA](https://cla.st.com).
* If you work for a company that wants also to allow you to contribute with your work, your company needs to provide a Corporate [CLA](https://cla.st.com) mentioning your GitHub account name.
* If you are not sure that a CLA (Individual or Corporate) has been signed for your GitHub account you can check the [CLA](https://cla.st.com) dedicated page.

Please note that:
* The Corporate CLA will always take precedence over the Individual CLA.
* One CLA submission is sufficient, for any project proposed by STMicroelectronics.

### 2.2 How to Proceed

1. **Engage first**: We recommend opening an issue first to discuss your proposal and confirm it aligns with STMicroelectronics' domain or scope.
2. **Fork the repository**: Fork the project to your GitHub account to develop your contribution. Please use the latest commit version.
3. **One PR per feature**: Submit one pull request per new feature or proposal. This eases the analysis and final merge process.
4. **Follow coding standards**: Ensure your code follows the existing code style and conventions in the repository.
5. **Test your changes**: Verify your changes work correctly and don't break existing functionality.
6. **Document your changes**: Update relevant documentation and add comments where necessary.

## 3. Support requests and questions

For support requests or any other question related to the product, the tools, the environment, you can submit a post to the **ST Community** on the appropriate topic [page](https://community.st.com/s/topiccatalog).

---

## 4. Commit Message Guidelines

To help maintain a clear history, please format your commit messages using the following convention:

```
[scope] short summary

Optional detailed description explaining the change.
```

### Format Rules
- **Scope**: One of the directories or areas affected (e.g., `api/certificate`, `doc`, `services`, `core`)
- **Short summary**: Present tense, no trailing period, under 72 characters, starting with a lowercase verb
- **Issue reference**: If related to an opened issue, append `#<number>` to the summary
- **Body**: Optional, but recommended when:
  - The summary exceeds 72 characters
  - Additional context would help reviewers understand the change
  - You want to explain the motivation or how this differs from previous behavior

### Examples
```
[api] add support for STSAFE-L010 authentication

[services/stsafea] fix frame encrypt/decrypt and MAC issues #123

[doc] update porting guide with clearer examples
```
