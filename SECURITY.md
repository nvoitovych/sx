# Security

sx handles secrets, so security reports get priority.

**Report privately**: email hi@nvlab.co with "sx security" in the subject, or use GitHub's
"Report a vulnerability" (private advisory) on this repository. Please do not open a public issue.

Include the version (`sx --version`), macOS version, and steps to reproduce. You will get an
answer within a week. There is no bug bounty.

In scope: anything that lets a process other than the signed `sx` CLI obtain secret values,
bypasses the approval card or a trusted `.sx.toml`, leaks values into logs or output, or lets an
agent change trust decisions. Known limits are listed in the README ("Limits") and are not bugs.
