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

init_git_repo

gittuf trust init -k ../keys/root
gittuf trust add-policy-key -k ../keys/root --policy-key ../keys/targets.pub
gittuf policy init -k ../keys/targets

# Add trusted person to gittuf policy file
gittuf policy add-person -k ../keys/targets --person-ID 'authorized-user' --public-key ../keys/authorized.pub

# Add branch protection rule
gittuf policy add-rule -k ../keys/targets --rule-name 'protect-main' --rule-pattern git:refs/heads/main --authorize authorized-user

# Stage and apply policy
gittuf policy stage --local-only
gittuf policy apply --local-only

echo 'Hello, world!' > README.md
git add README.md
git commit -m 'Initial commit'

gittuf rsl record main --local-only

# This will succeed!
gittuf verify-ref main

# Simulate violation by using unauthorized key
git config --local user.signingkey ../keys/unauthorized

echo 'This is not allowed!' >> README.md
git add README.md
git commit -m 'Update README.md'

gittuf rsl record main --local-only

set +e

# This will fail as branch protection rule is violated!
gittuf verify-ref main

if [ $? -ne 1 ]; then
    exit 1
fi

set -e

# Rewind to known good state
git reset --hard HEAD~1
git update-ref refs/gittuf/reference-state-log refs/gittuf/reference-state-log~1
git config --local user.signingkey ../keys/authorized

# Add file protection rule
gittuf policy add-rule -k ../keys/targets --rule-name 'protect-readme' --rule-pattern file:README.md --authorize authorized-user

# Stage and apply policy
gittuf policy stage --local-only
gittuf policy apply --local-only

# Make change to README.md using unauthorized key
git config --local user.signingkey ../keys/unauthorized

echo 'This is not allowed!' >> README.md
git add README.md
git commit -m 'Update README.md'

# But record RSL entry using authorized key to meet branch protection rule
git config --local user.signingkey ../keys/authorized
gittuf rsl record main --local-only

set +e

# This will fail as file protection rule is violated!
gittuf verify-ref main

if [ $? -ne 1 ]; then
    exit 1
fi

set -e

# Rewind to known good state
git reset --hard HEAD~1
git update-ref refs/gittuf/reference-state-log refs/gittuf/reference-state-log~1
git config --local user.signingkey ../keys/authorized

# Add tag protection rule
gittuf policy add-rule -k ../keys/targets --rule-name 'protect-releases' --rule-pattern "git:refs/tag/v*" --authorize authorized-user

# Stage and apply policy
gittuf policy stage --local-only
gittuf policy apply --local-only

# Tag v1 using unauthorized key
git config --local user.signingkey ../keys/unauthorized
git tag v1 -m "Unauthorized release"

# Record to RSL and verify tag
gittuf rsl record v1 --local-only

set +e

# This will fail as tag protection rule is violated!
gittuf verify-ref --verbose refs/tags/v1

if [ $? -ne 1 ]; then
    exit 1
fi

echo "Test completed successfully!"
