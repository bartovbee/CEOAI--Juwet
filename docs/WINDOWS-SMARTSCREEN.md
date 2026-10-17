# Windows SmartScreen notice (unsigned build)

## Why Windows may show a warning

The current CI-produced `CEOAI-Juwet.exe` is not signed with a code-signing certificate. Windows SmartScreen may therefore show an “unrecognized app” warning. This warning is not proof that the file is malicious, and the absence of a warning would not prove a file is safe.

## Before running the executable

1. Obtain the ZIP only from the project's trusted GitHub Actions run/artifact page or another release location explicitly designated by the project maintainer.
2. Check that the artifact belongs to the expected commit and CI run. For the build described in PR #2, the uploaded artifact's SHA-256 is recorded in the workflow artifact metadata; verify it against the published value before using the file.
3. Do not run the file if the source, commit, artifact, or checksum cannot be verified, or if the file came from an unexpected link.

## If SmartScreen appears

Only proceed if you intentionally downloaded the expected artifact from the trusted project source and verified it:

1. In the Windows warning dialog, select **More info**.
2. Check the displayed application/publisher details. Because this build is unsigned, a verified publisher may not be shown.
3. Select **Run anyway** only if the file and its origin match the expected project artifact.

If anything does not match, choose **Don't run** and contact the project maintainer. Do not disable SmartScreen globally or lower Windows security settings to run this application.

## Current limitation

This is an unsigned CI build, not a signed production release. A future release should use a trusted code-signing certificate and publish checksum information through a trusted release channel.