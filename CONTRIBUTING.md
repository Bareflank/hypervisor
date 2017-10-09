## Contributors License Agreement
To get started, <a href="https://www.clahub.com/agreements/Bareflank/hypervisor">sign the Contributor License Agreement</a>.

## Forking

Before you can contribute, you must fork the repo that you wish to contribute to. GitHub already has great documentation on how to fork a repo, make a modification, and create a pull request. If you are not familiar with this process, please read the following before continuing:

https://help.github.com/articles/fork-a-repo <br>
https://help.github.com/articles/using-pull-requests

## Questions

This project provides multiple methods for asking other community members questions about the project. All questions are welcome, but prior to asking a question, please ensure that existing documentation and / or previous Q&As have not already answered your question prior to submission.

**Bug Tracking / RFCs / Feature Requests / Questions:** <br>
https://github.com/Bareflank/hypervisor/issues

**IRC / Gitter:** <br>
https://gitter.im/Bareflank-hypervisor/Lobby

## Feature Requests

Feature requests are always welcome as they help to drive the creation of future roadmaps by the community. Please submit all feature requests to the GitHub Bug Tracker with “Feature Request:” prepended to the message’s title. Doing so provides a means for community members to filter and comment on the feature requests, ask questions, and provide input.

**Feature Requests:** <br>
https://github.com/Bareflank/hypervisor/issues

If a feature request already exists, please use the existing feature request message, and add a “+1” comment to show your desire for the feature. Features requests with higher community support are more likely to be added to the roadmap.

## Reporting Issues / Vulnerabilities

All issues and vulnerabilities should be submitted to the following issue tracker:

**Bug Tracking:** <br>
https://github.com/Bareflank/hypervisor/issues

When submitting an issue, please include the following documentation:

- Title
- Brief description of the issue
- Instructions for how to reproduce the issue
- Version information (or commit hash)
- Environment information (distribution, supporting library information, compiler, hardware)
- Console logs (if applicable)
- Backtrace logs (if applicable)

## Request for Comments

Prior to submitting changes to the project, a Request for Comments (RFC) is highly advised. An RFC provides the community with an opportunity to provide feedback prior to submission. The submitter should view the RFC as a chance to gain community support early, reducing the likelihood of push back during submission.

All RFCs should be submitted to the project’s GitHub Bug Tracker with “RFC:” prepended to the message’s title. Doing so provides a means for community members to filter and comment on the RFC, ask questions, and provide input.

**RFCs:** <br>
https://github.com/Bareflank/hypervisor/issues

Although an RFC can take on any format, please ensure that an RFC includes the following:

- Title
- TL;DR (summary)
- Detailed description
- Proposed API changes (if applicable)
- Proposed documentation changes (if applicable)
- Proposed testing changes (if applicable)

Although an RFC should contain as much information as possible to reduce the number of questions likely to be asked by the community, it should also be as brief as possible. RFCs that are too long will likely see limited community involvement, resulting in a higher risk of push back during the submission of any proposed changes.

## Pull Requests / Commit Message Format

Anyone can submit a pull request to the project. All pull requests must satisfy the requirements defined in the governance documentation. If the pull request includes source code, tests for the source code must also be included (usually in the form of unit tests). All CI tests must also return without error, demonstrating that not only does the source code contain the proper tests to validate it’s implementation, but these tests succeed.

This project uses Astyle to format the source code, and the project provides a configuration file (astyle.conf) that should be used. Prior to submitting changes to the project, all source code should be run through Astyle to verify that the proper formatting rules are applied. If this is not done, Travis CI will fail when the PR is submitted. To format the code run "make astyle" and "make astyle_clean" when complete.

Clang Tidy and Google's Sanitizers are used to perform static / dynamic analysis. If a PR fails because of these checks you can run them locally, or review the Travis CI log. To perform the Clang Tidy checks on Linux, install [bear](https://github.com/rizsotto/Bear) and run:

```
make clean
STATIC_ANALYSIS_ENABLED=true bear make
make tidy
```

To perform the Google Sanitizer checks run:

```
make clean
DYNAMIC_ANALYSIS_ENABLED=true make
make test
```

All whitespace should be removed as well. Use "git diff --check" to ensure the PR does not contain added whitespace. Doxygen is also used by this project. Prior to submitting a PR, please run "make doxygen" and "make doxygen_clean" to ensure there are no errors with respect to the documentation.

Prior to submitting a PR, please rebase your git history to a single commit. To do this:

```
git fetch <upstream remote>
git rebase -i <upstream remote>/master
    "pick -> r" for the top commit
    "pick -> f" for the rest of the commits
```

All commits to the project should have the following commit format. The information used in this commit format provides the community with a means to create the project’s changelog, as well as identify what each commit addresses.

- Title (50 characters or less)
- Empty line
- Description (wrapped to 72 characters per line)
- Empty line
- \[ISSUE\]: link (if applicable)
- \[RFC\]: link (if applicable)
- Empty line
- Sign-off

For Example:

```
Added new API XYZ

The library was missing the ability to do blah, and as a
result, blah was not possible. The following commit adds
XYZ to the project providing the ability to:

- Do blah blah
- And blah
- As well as blah

The following blah was added to the unit tests to validate
that this new API works as intended.

[RFC]: link

Signed-off-by: John Smith <smithj@company.com>
```

## API Documentation

All functions should be documented using Doxygen style comment blocks. Each comment block should define the following:

- All parameters and their expected values
- Return value (if applicable)
- Error cases
- Notes (if applicable)
- Code Example (if applicable)

Since comments are kept to a minimum, the function’s comment block is a great place to put notes about the function’s implementation. For more information about Doxygen, please see:

[Doxygen Manual](http://www.stack.nl/~dimitri/doxygen/)

## Tagged Releases

Major tags will be managed by the community, and signify milestones in the project’s roadmap. It is up to the community members to maintain major tags, and there are currently no guarantees on the life-time of a tagged version of this project.

At any point in time, a community member can request a minor tagged version of the project via an RFC. Minor tags are managed by the community member(s) that requested the tag. The request should include:

- What to tag (git hash)
- Who’s requesting the tag
- How long the community member(s) plan to maintain the tag
- Level of testing being applied to the tag
- Supported configurations

Since more than one organization could be basing their products off of this project, minor tags provide an organization with a means to baseline the project, and provide others with some of the maintenance and stability the organization is likely to provide. The alternative would be the organization maintains an internal, stable fork of the project, that others cannot benefit from.

## Roles and Responsibilities

The following defines the different roles that make up this project, as well as defines the responsibilities for each of these roles. These roles are based on a meritocratic, community owned governance model, and as such, all changes to the project are communicated, and voted on prior to approval. The project as a whole is owned by the community members, and it’s vision and goals are defined by the community.

This governance model strives to provide all members of the community with a voice, and has no special requirements for community members to be given a vote on changes to the project. In the event community consensus cannot be reached, a small subset of community members have the authority to vote on a resolution.

### Users

Users are community members who use the project. There are no requirements to be a user of this project. Users can contribute back to the project in multiple ways including:

- Using the project
- Advertising the project to others (word-of-mouth, website links, reviews, etc…)
- Reporting issues
- Providing new feature requests
- Providing financial support
- Providing moral support (a thank you goes a long way)

### Contributors

Contributors are community members who contribute to the project in one way or another. There are no special requirements to how much a community member must contribute to be a contributor. Since anyone can be a contributor, this project does, however, provide a set of guidelines that defines what, when and how contributions are accepted by the community. In addition to the responsibilities of a user, a contributor contributes changes to the project. This includes (but is not limited to, and nor does it require):

- New features
- Bug fixes
- Design documentation
- Installation documentation
- Usage documentation
- API documentation
- Graphics / web design
- Commenting on RFCs
- Voting on changes to the project
- General feedback

All contributions made to the project should be socialized with the community to increase the chances of acceptance. For new features, this is down via a Request For Comments (RFC). Bug fixes should be reported using the issue tracker, and provided as a patch (or pull request) to the community.

All contributors have the right to vote on changes to the project prior to their acceptance, providing an equal opportunity for everyone’s voice to be heard. This includes providing feedback on RFCs, solutions to currently tracked bugs, and all other changes that are made to the project. Since there are no special requirements to be a contributor, everyone’s opinion must be considered, regardless of their involvement in the project. If a general consensus cannot be made, the project owners are responsible for voting to resolve the conflict.

### Owners

Owners are community members who own the project. Owners have little responsibility over and above a contributor. Their primary goal is to commit changes to the project, and resolve conflicts. The responsibilities of an owner includes that of a user and contributor, while also including:

- Committing changes to the project
- Voting on changes to the project when a consensus cannot be reached among the contributors.
- Voting on the addition / removal of owners

Although owners have the ability to commit a change to the project, they are still required to get consensus from the contributors. Ideally, the entire community would agree on a specific change, unanimously. In the case where an agreement cannot be made, the owners are responsible for voting to resolve the conflict.

## Conflict Resolution

This project uses a form of lazy consensus to approve and disapprove changes to the project. When a change is proposed (could be a pull request, RFC, etc…), 48 hours should be provided to give all community members an opportunity to comment if so desired, prior to an owner committing the change to the project.

Community members approve a change to the project by stating +1, or not stating anything at all (i.e. silence is consent). If a community member objects (i.e. -1), that community member is responsible for providing an alternative approach to the proposed change. Failure to do so is equivalent to a +1 and shall be treated as such (i.e. simply objecting is not tolerated, and will be treated as consent).

It is likely that at some point, the community will not agree on a proposed change (i.e. unanimous consent was not reached, or in other words, at least one contributor provides a -1 with an alternative approach). If this should occur, the owners of the project are responsible for resolving the conflict. Once a vote is taken up by the owners, 48 hours should be provide for all of the owners to have an opportunity to comment if so desired. Like the community, owners use a lazy consensus model. A +1 or silence states approval by an owner. The difference is, a -1 by an owner during the vote to resolve a conflict does _not_ need to be accompanied by a proposed alternative. Majority vote wins. In the event of a tie, no action is taken, and the community must work towards an alternate solution that does not result in a tie.
