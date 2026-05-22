package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

func mustStore() *relay.Store {
	dsn, err := resolveDSN(os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_URL_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	s, err := relay.NewStore(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		os.Exit(1)
	}
	return s
}

func runInviteCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: relay invite create|list|revoke")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("invite create", flag.ExitOnError)
		label := fs.String("label", "", "optional admin-side label")
		uses := fs.Int("uses", 1, "max uses")
		days := fs.Int("expires-days", 7, "expiry in days")
		_ = fs.Parse(args[1:])
		s := mustStore()
		defer s.Close()
		code, err := relay.GenerateInviteCode()
		if err != nil {
			fatal(err)
		}
		exp := time.Now().Add(time.Duration(*days) * 24 * time.Hour)
		if err := s.CreateInvite(relay.HashInviteCode(code), nil, *label, *uses, exp); err != nil {
			fatal(err)
		}
		fmt.Println(code)
		fmt.Fprintf(os.Stderr, "expires %s · %d use(s)\n", exp.Format(time.RFC3339), *uses)
	case "list":
		s := mustStore()
		defer s.Close()
		list, err := s.ListInvites()
		if err != nil {
			fatal(err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "HASH\tLABEL\tUSES\tEXPIRES\tREVOKED")
		for _, inv := range list {
			revoked := ""
			if inv.RevokedAt != nil {
				revoked = inv.RevokedAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%s\n",
				inv.CodeHash[:12], inv.Label, inv.UsedCount, inv.MaxUses,
				inv.ExpiresAt.Format(time.RFC3339), revoked)
		}
		tw.Flush()
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: relay invite revoke <hash>")
			os.Exit(2)
		}
		s := mustStore()
		defer s.Close()
		if err := s.RevokeInvite(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintf(os.Stderr, "unknown invite subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func runUserCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: relay user list|remove")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		s := mustStore()
		defer s.Close()
		list, err := s.ListUsers()
		if err != nil {
			fatal(err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tADMIN\tCREATED")
		for _, u := range list {
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n",
				u.ID, u.DisplayName, u.IsAdmin, u.CreatedAt.Format(time.RFC3339))
		}
		tw.Flush()
	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: relay user remove <id>")
			os.Exit(2)
		}
		s := mustStore()
		defer s.Close()
		if err := s.DeleteUser(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintf(os.Stderr, "unknown user subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
