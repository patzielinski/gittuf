# gittuf E2E Test: Policy Rollback via RSL

# Exit on nonzero return code
set -e

init_git_repo() {
    cd $(mktemp -d)

    mkdir {keys,repo}
    
    cd keys
    ssh-keygen -q -t ecdsa -N "" -f root
    ssh-keygen -q -t ecdsa -N "" -f targets
    ssh-keygen -q -t ecdsa -N "" -f authorized
    ssh-keygen -q -t ecdsa -N "" -f unauthorized

    cd ../repo

    git init -b main
    git config --local gpg.format ssh
    git config --local commit.gpgsign true
    git config --local tag.gpgsign true
    git config --local user.signingkey ../keys/authorized
    git config --local user.name gittuf-demo
    git config --local user.email gittuf.demo@example.com
}

# Part 1: Test on a single repository

init_git_repo

CONTROLLER_REPOSITORY="$(pwd)"
CONTROLLER_ROOT_KEY="$CONTROLLER_REPOSITORY/../keys/root"

gittuf trust init -k ../keys/root
gittuf trust make-controller -k ../keys/root
gittuf trust add-policy-key -k ../keys/root --policy-key ../keys/targets.pub
gittuf policy init -k ../keys/targets
gittuf policy add-person -k ../keys/targets --person-ID 'authorized-user' --public-key ../keys/authorized.pub

gittuf policy stage --local-only
gittuf policy apply --local-only

# Check no violation with "unauthorized" key due to no branch protection rule active
git config --local user.signingkey ../keys/unauthorized

echo 'Hello, world!' > README.md
git add README.md
git commit -m 'Initial commit'
gittuf rsl record main --local-only

# This will succeed, this is OK.
gittuf verify-ref main

# Add branch protection rule; stage and apply policy
git config --local user.signingkey ../keys/authorized
gittuf policy add-rule -k ../keys/targets --rule-name 'protect-main' --rule-pattern git:refs/heads/main --authorize authorized-user
gittuf policy stage --local-only
gittuf policy apply --local-only

# Simulate violation by using unauthorized key
git config --local user.signingkey ../keys/unauthorized

echo 'Hello, world!!' > README.md
git add README.md
git commit -m 'Another commit'
gittuf rsl record main --local-only

# This will fail as branch protection rule is violated, this is OK.
if gittuf verify-ref main; then
    echo "Test failed on branch protection rule check"
    exit 1
fi

# Rewind main branch and RSL to known good state
git reset --hard HEAD~1
git update-ref refs/gittuf/reference-state-log refs/gittuf/reference-state-log~1

# Switch to unauthorized key
git config --local user.signingkey ../keys/unauthorized

# Dump current policy commit hash
POLICY_HEAD="$(git show -s --format='%H' refs/gittuf/policy)"

# Rewind policy ref temporarily to use gittuf to record the previous hash
git update-ref refs/gittuf/policy refs/gittuf/policy~1
git show -s --format='%H' refs/gittuf/policy

# Record RSL entry with this previous policy
gittuf rsl record refs/gittuf/policy --local-only

# Restore policy back to previous tip
git update-ref refs/gittuf/policy $POLICY_HEAD

echo 'Hello, world!!!' > README.md
git add README.md
git commit -m 'Evil commit'

# Record commit to RSL
gittuf rsl record main --local-only

# This should NOT succeed
if gittuf verify-ref main; then
    echo "Test failed on policy rollback"
    exit 1
fi

# Part 2: Test with a downstream repository

init_git_repo

DOWNSTREAM_REPOSITORY="$(pwd)"

# Set up repo and add first repo as controller
gittuf trust init -k ../keys/root
gittuf trust add-policy-key -k ../keys/root --policy-key ../keys/targets.pub
gittuf policy init -k ../keys/targets
gittuf policy add-person -k ../keys/targets --person-ID 'authorized-user' --public-key ../keys/authorized.pub
gittuf trust -k ../keys/root add-controller-repository --location $CONTROLLER_REPOSITORY --name controller-repo --initial-root-principal $CONTROLLER_ROOT_KEY

gittuf policy stage --local-only
gittuf policy apply --local-only

# This should NOT succeed
if gittuf rsl propagate; then
    echo "Test failed on controller repository check"
    exit 1
fi

echo "Test completed successfully!"
