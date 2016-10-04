// Copyright © 2016 Kevin Kirsche
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
	git "github.com/libgit2/git2go"
	"github.com/spf13/cobra"
)

var (
	approvedDomains []string
	gitUser         string
	gitPassword     string
	filePath        string
	pushOnWrite     bool
	verbose         bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "notify-git",
	Short: "Used to monitor a file for changes and notify git to push it to the cloud",
	Long: `Notify git is a tool designed to monitor a single file for changes
and notify git when a change is detected. The tool will then attempt to push the
change to the remote repository, if enabled with --push-on-write / -w.

Example:

notify-git -w -u username -p password -f /Library/Security/PolicyBanner.rtf
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		} else {
			logrus.SetLevel(logrus.InfoLevel)
		}
		logrus.Debugf("Git username: `%s`", gitUser)
		logrus.Debugf("Git password: `%s`", gitPassword)
		logrus.WithField("approved-domains", approvedDomains).Debugln("Approved certificate domains")

		filePathArray := strings.Split(filePath, "/")

		gitRepoPath := strings.Join(filePathArray[:len(filePathArray)-1], "/")
		logrus.Debugf("Git repository path: `%s`", gitRepoPath)

		fileName := filePathArray[len(filePathArray)-1]
		logrus.Debugf("File to be monitored: `%s`", fileName)

		repo, err := git.OpenRepository(gitRepoPath)
		if err != nil {
			logrus.WithError(err).Fatalln("Failed to create new watcher.")
		}

		index, err := repo.Index()
		if err != nil {
			logrus.WithError(err).Fatalln("Failed to retrieve git index for repository.")
		}

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logrus.WithError(err).Fatalln("Failed to create new watcher.")
		}
		defer watcher.Close()

		done := make(chan bool)
		doneWatch := make(chan bool)
		commitNeeded := make(chan time.Time)

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for _ = range c {
				fmt.Println("")
				logrus.Debugln("Ctrl + C captured.")
				logrus.Infoln("Cleaning up...")
				doneWatch <- true
				done <- true
			}
		}()

		go func() {
			for {
				logrus.Debugln("Waiting for watcher event in goroutine...")
				select {
				case <-doneWatch:
					// If we don't return, we get a ton of <nil> and "" events and errors.
					return
				case event := <-watcher.Events:
					logrus.WithField("event", event.String()).Debugln("Watcher event received.")
					if event.Op&fsnotify.Write == fsnotify.Write {
						changedTime := time.Now()
						commitNeeded <- changedTime
						logrus.Debugln("Message sent to channel")
					}
				case caseErr := <-watcher.Errors:
					if caseErr != nil {
						logrus.WithError(caseErr).Errorln("Received error from file watcher.")
					}
				}
			}
		}()

		err = watcher.Add(filePath)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to begin watching file.")
			return
		}

	watcherLoop:
		for {
			logrus.Debugln("Waiting for watcher event on channel...")
			select {
			case <-done:
				break watcherLoop
			case changedTime := <-commitNeeded:
				if pushOnWrite {
					logrus.Debugln("Retrieving git repository index")
					err = index.AddByPath(fileName)
					if err != nil {
						logrus.WithError(err).Errorln("Failed to add file to git index.")
						return
					}

					logrus.Debugln("Writing tree to repository.")
					treeID, err := index.WriteTree()
					if err != nil {
						logrus.WithError(err).Errorln("Failed to write tree to repository.")
						return
					}

					logrus.Debugln("Writing index to disk.")
					err = index.Write()
					if err != nil {
						logrus.WithError(err).Errorln("Failed to write index.")
						return
					}

					logrus.Debugln("Retrieving our new tree object.")
					tree, err := repo.LookupTree(treeID)
					if err != nil {
						logrus.WithError(err).Errorln("Failed to lookup tree within repository.")
						return
					}

					branch, err := repo.LookupBranch("master", git.BranchLocal)
					if err != nil {
						logrus.WithError(err).Errorln("Failed to lookup master branch within repository.")
						return
					}

					commitTarget, err := repo.LookupCommit(branch.Target())
					if err != nil {
						logrus.WithError(err).Errorln("Failed to retrieve commit target.")
						return
					}

					sig := &git.Signature{
						Name:  "Kevin Kirsche",
						Email: "kevin.kirsche@verizon.com",
						When:  changedTime,
					}

					msg := fmt.Sprintf("[Automated] File %s changed at %s.", filePath, changedTime.String())

					logrus.Debugln("Creating commit.")
					_, err = repo.CreateCommit("HEAD", sig, sig, msg, tree, commitTarget)
					if err != nil {
						logrus.WithError(err).Errorln("Failed to create commit within repository.")
						return
					}

					logrus.Debugln("Retrieving remote repository")
					remote, err := repo.Remotes.Lookup("origin")
					if err != nil {
						logrus.WithError(err).Errorln("Failed to lookup git remote 'origin'.")
						return
					}

					pushOpts := &git.PushOptions{
						RemoteCallbacks: git.RemoteCallbacks{
							CredentialsCallback:      credentialsCallback,
							CertificateCheckCallback: certificateCheckCallback,
						},
					}

					logrus.Debugln("Attempting to push to remote repository")
					err = remote.Push([]string{"refs/heads/master"}, pushOpts)
					if err != nil {
						logrus.WithError(err).Debugln("Failed to push commit to remote server.")
					}
				}
			}
		}

		close(done)
		close(doneWatch)
		close(commitNeeded)
		watcher.Close()
		logrus.Infoln("Exiting...")
	},
}

func credentialsCallback(url, username_from_url string, allowed_types git.CredType) (git.ErrorCode, *git.Cred) {
	ret, cred := git.NewCredUserpassPlaintext(gitUser, gitPassword)
	return git.ErrorCode(ret), &cred
}

func certificateCheckCallback(cert *git.Certificate, valid bool, hostname string) git.ErrorCode {
	match := false

	for _, domain := range approvedDomains {
		if hostname == strings.TrimSpace(domain) {
			match = true
		}
	}

	if !match {
		return git.ErrUser
	}

	return git.ErrorCode(0)
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enables verbose mode")
	RootCmd.Flags().BoolVarP(&pushOnWrite, "push-on-write", "w", false, "Enables git push on write")
	RootCmd.Flags().StringVarP(&filePath, "file-path", "f", "", "Path to file to monitor")
	RootCmd.Flags().StringVarP(&gitUser, "git-user", "u", "", "Sets the username to use when prompted for credentials")
	RootCmd.Flags().StringVarP(&gitPassword, "git-password", "p", "", "Sets the password to use when prompted for credentials")
	RootCmd.Flags().StringSliceVarP(&approvedDomains, "approved-domains", "a", []string{"github.com"}, "Set of approved domains to allow during certificate check")
}
