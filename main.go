package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	git "github.com/ossf/scorecard/v4/clients/git"
	"github.com/ossf/scorecard/v4/clients/localdir"

	"github.com/ossf/scorecard/v4/checker"
	sclog "github.com/ossf/scorecard/v4/log"
	"github.com/ossf/scorecard/v4/pkg"
)

var signedCommits = "CheckSignedCommits"
var gradleWrapperJar = "CheckGradleWrapperJar"
var gradleWrapperJarChecksums = []string{
	"d3b261c2820e9e3d8d639ed084900f11f4a86050a8f83342ade7b6bc9b0d2bdd", // release-2v8.5
	"0336f591bc0ec9aa0c9988929b93ecc916b3c1d52aed202c7381db144aa0ef15", // release-2v8.4
	"14dfa961b6704bb3decdea06502781edaa796a82e6da41cd2e1962b14fbe21a3", // release-2v7.6.3
	"5e27c39c2336c25748f279d8b105162d14b1a39eb7839d0b658432282d0ce79f", // release-2v2.1
	"80a33ca14e3bca3116bc8749550397f739f126190c82bb6399fdc8d10f49661f", // release-2v2.0
	"dea5ceba47b58df0b7f69a65b24357527c1927ccc72b6d4ed90658d39e461b29", // release-2v1.12
	"a14b54dd3790f5ce1dc08ebbf4b5bcc05f76c4554b43accb84696c970f29aba0", // release-2v1.11
	"6a6c15e222a0458aa33985b87f67954f4222410b43b1e26866197d0a77d93cbc", // release-2v1.10
	"91941f522fbfd4431cf57e445fc3d5200c85f957bda2de5251353cf11174f4b5", // release-2v8.0
	"c5a643cf80162e665cc228f7b16f343fef868e47d3a4836f62e18b7e17ac018a", // release-2v7.6
	"e996d452d2645e70c01c11143ca2d3742734a28da2bf61f25c82bdc288c9e637", // release-2v6.9.3
	"91a239400bb638f36a1795d8fdf7939d532cdc7d794d1119b7261aac158b1e60", // release-2v7.5.1
	"91a239400bb638f36a1795d8fdf7939d532cdc7d794d1119b7261aac158b1e60", // release-2v7.5
	"c95985b7b5684e133c5d45044fd90faaf6c8f7cd2493d61a11c2b8c5b71ef514", // release-2v1.4
	"22c56a9780daeee00e5bf31621f991b68e73eff6fe8afca628a1fe2c50c6038e", // release-2v1.1
	"87e50531ca7aab675f5bb65755ef78328afd64cf0877e37ad876047a8a014055", // release-2v1.0
}

var url = "/Users/naveen/go/src/github.com/naveensrinivasan/eladmin-1"

func main() {
	ctx := context.Background()
	logger := sclog.NewLogger(sclog.WarnLevel)
	repo, err := localdir.MakeLocalDirRepo(url)
	if err != nil {
		return
	}
	checksToRun := make(checker.CheckNameToFnMap)
	checksToRun[gradleWrapperJar] = checker.Check{
		Fn:                    checkGradleWrapperJar,
		SupportedRequestTypes: []checker.RequestType{checker.FileBased, checker.CommitBased},
	}

	repo, _, ossFuzzRepoClient, ciiClient, vulnsClient, err := checker.GetClients(
		ctx, "", url, logger)
	client := git.Client{}
	err = client.InitRepo(repo, "HEAD", 10)
	if err != nil {
		return
	}
	scorecard, err := pkg.RunScorecard(ctx, repo, "HEAD", 100, checksToRun, &client, ossFuzzRepoClient, ciiClient, vulnsClient)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, checkResult := range scorecard.Checks {
		fmt.Println(checkResult.Name)
		fmt.Println(checkResult.Details)
		fmt.Println(checkResult.Score)
	}
}
func checkSignedCommits(request *checker.CheckRequest) checker.CheckResult {
	commits, err := request.RepoClient.ListCommits()
	if err != nil {
		return checker.CreateRuntimeErrorResult(signedCommits, err)
	}
	signedCommits := 0
	for _, commit := range commits {
		if strings.Contains(commit.Message, "Signed-off-by:") {
			signedCommits++
		}
	}
	proportionalScore := (signedCommits / len(commits)) * checker.MaxResultScore
	if proportionalScore == checker.MaxResultScore {
		return checker.CreateMaxScoreResult("CheckSignedCommits", "all commits are signed off")
	} else {
		return checker.CreateResultWithScore("CheckSignedCommits", fmt.Sprintf("%d%% of commits are signed off", proportionalScore), proportionalScore)
	}
}

func checkGradleWrapperJar(request *checker.CheckRequest) checker.CheckResult {
	files, err := request.RepoClient.ListFiles(func(x string) (bool, error) {
		// if string contains gradle-wrapper.jar
		if strings.Contains(x, ".jar") {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return checker.CreateRuntimeErrorResult(signedCommits, err)
	}
	maxScore := checker.MaxResultScore
	reason := ""
	for _, file := range files {
		shaSumBytes, err := GetShaSum(fmt.Sprintf("%s/%s", url, file))
		if err != nil {
			return checker.CreateRuntimeErrorResult(signedCommits, err)
		}
		found := false
		shaSum := hex.EncodeToString(shaSumBytes) // Convert to he
		fmt.Println(shaSum, file)
		for _, gradleWrapperJarChecksum := range gradleWrapperJarChecksums {
			if shaSum == gradleWrapperJarChecksum {
				found = true
				break
			}
		}
		if !found {
			reason = fmt.Sprintf("Checksum of %s does not match any of the known checksums", file)
			maxScore--
		}
	}
	if maxScore == checker.MaxResultScore {
		return checker.CreateMaxScoreResult("CheckGradleWrapperJar", "all gradle-wrapper.jar files have known checksums")
	}
	return checker.CreateResultWithScore("CheckGradleWrapperJar", reason, maxScore)
}

type QueryResult struct {
	Versions []Version
}

type Version struct {
	VersionKey VersionKey
}

type VersionKey struct {
	System  string
	Name    string
	Version string
}

func GetShaSum(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Compute the SHA-256 hash of the file's contents
	hash := sha256.Sum256(data)
	return hash[:], nil
}
