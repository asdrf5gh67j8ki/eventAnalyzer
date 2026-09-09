# Publish eventAnalyzer 1.0.0

The repository contains source code. The Windows release download contains the
built executable, an example, a quick start, build information, and a dependency
license. GitHub Actions builds and tests that download for you.

## 1. Put the source on GitHub

Extract `eventAnalyzer-github-ready.zip` to a new folder. Open PowerShell in its
`eventAnalyzer` folder, where `CMakeLists.txt` lives.

On GitHub, create an empty repository named `eventAnalyzer`. Choose Public if
you want it visible in your portfolio. Leave the options to initialize a README,
license, and gitignore unchecked; upload the files from this folder instead.

With Git for Windows installed, run the following, replacing `YOUR_USERNAME`:

```powershell
git init -b main
git add .
git status --short
git commit -m "Prepare eventAnalyzer 1.0.0 release"
git remote add origin https://github.com/YOUR_USERNAME/eventAnalyzer.git
git push -u origin main
```

Authenticate in the browser if Git prompts. If Git requests your author identity,
run these in this folder, substituting your own name and commit email, then
repeat the commit and push:

```powershell
git config user.name "YOUR_NAME"
git config user.email "YOUR_GITHUB_COMMIT_EMAIL"
```

Your GitHub email settings show your private noreply commit address if you use one.

If you already have a repository with history, copy these project files into its
existing checkout, preserving that checkout's `.git` directory. Commit and push
the changes there; skip `git init` and `git remote add`. Do not force-push over
existing work. The commands below assume its branch is `main`.

Keep `vendor/` in the repository: CMake compiles those bundled dependencies.
Build folders, generated databases, and `dist/` are ignored.

## 2. Download the tested executable

Open **Actions → build-and-test** and select the run for your pushed commit.
Wait for all three jobs to be green:

- Windows x64 release
- Linux release tests
- Address and undefined behavior sanitizers

The Windows job builds x64 with the static MSVC runtime, runs both test suites,
creates a ZIP, extracts it, and checks the demo plus duplicate handling. Python
is installed explicitly so the CLI suite cannot be skipped for lack of Python.

At the bottom of the run page, download the artifact **eventAnalyzer-windows-x64**.
You must be signed into GitHub to download workflow artifacts. Extract that
artifact download to obtain these two release assets:

```text
eventAnalyzer-v1.0.0-windows-x64.zip
eventAnalyzer-v1.0.0-windows-x64.zip.sha256
```

The artifact download is an outer ZIP. Publish the two files inside it.
The SHA-256 file contains the checksum of the inner Windows ZIP.

In PowerShell, from the folder containing those files, verify the checksum:

```powershell
$eaArchive = '.\eventAnalyzer-v1.0.0-windows-x64.zip'
$eaExpected = ((Get-Content ($eaArchive + '.sha256') -Raw).Trim() -split '\s+')[0]
$eaActual = (Get-FileHash $eaArchive -Algorithm SHA256).Hash
if($eaActual -ne $eaExpected){ throw 'The release ZIP checksum does not match.' }
```

Extract the inner ZIP, open PowerShell in its extracted folder, and follow its
`README.md`. It should report version `1.0.0`, import four events, and produce
three alerts. The source commit is recorded in `BUILD-INFO.txt`.

## 3. Tag exactly the commit that passed

Back in the source checkout, use the full source commit SHA from `BUILD-INFO.txt`:

```powershell
git tag -a v1.0.0 TESTED_COMMIT_SHA -m "eventAnalyzer 1.0.0"
git push origin v1.0.0
```

Replace `TESTED_COMMIT_SHA` before running. Do not move an existing published
tag. If `v1.0.0` already exists, use its matching build or prepare a new version.

The tag push also runs the workflow; wait for that run to pass. You can use its
artifact for the release. The packaging script checks that the tag agrees with
the version in `CMakeLists.txt` and the executable.

## 4. Publish the release

Open **Releases → Draft a new release**. Choose the existing `v1.0.0` tag and
enter **eventAnalyzer 1.0.0** as the title. Paste the notes from
[`release-notes-v1.0.0.md`](release-notes-v1.0.0.md).

Attach both the Windows ZIP and its `.sha256` file, then click **Publish release**.
Leave the prerelease option off for this stable release. GitHub adds source-code
archives automatically; users who want to run it should download the Windows ZIP.

## Optional: build the same package locally

GitHub Actions handles the build, so these commands are only needed if you want
to reproduce the package on your own machine. For Visual Studio 2026 with the
Desktop development with C++ workload, CMake 4.2 or newer, and Python 3 on PATH,
run from the source root:

```powershell
cmake -S . -B build-release -G "Visual Studio 18 2026" -A x64 -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DBUILD_TESTING=ON -DEA_WARNINGS_AS_ERRORS=ON
cmake --build build-release --config Release --parallel
ctest --test-dir build-release -C Release --output-on-failure
python .\tools\package_release.py --exe .\build-release\Release\eventAnalyzer.exe
```

Stop if a command fails. Confirm CTest runs both `core` and `cli` before
packaging. For Visual Studio 2022, use `-G "Visual Studio 17 2022"` instead;
CMake 3.24 or newer is sufficient for that generator.

Use this fresh `build-release` directory because an existing Ninja/x86 build
cache cannot be reused for the Visual Studio/x64 configuration. The files to
publish are created in `dist/`.

## References

- [GitHub: downloading workflow artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)
- [GitHub: managing releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- [CMake: MSVC runtime selection](https://cmake.org/cmake/help/latest/variable/CMAKE_MSVC_RUNTIME_LIBRARY.html)
- [CMake: Visual Studio 2026 generator](https://cmake.org/cmake/help/latest/generator/Visual%20Studio%2018%202026.html)
