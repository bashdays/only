#!/bin/sh
# leg20170302: CC0, Public Domain
#
# 'only' is a utility to be run via ssh as a 'command' specified for a
# public key in the `authorized_keys` file.  It checks if the command
# in SSH_ORIGINAL_COMMAND is listed as one of the parameters specified
# on 'only's commandline and runs it if the command line arguments in
# SSH_ORIGINAL_COMMAND are allowed by the rules found in the rule file
# ~/.onlyrules.  'only' refuses to run commands if the rule file does
# not exist.
#
# You can enable command line substitution by creating a ~/.onlyrc
# file with the token 'enable_command_line_substitution' on a single
# line.  This is not encouraged for security reasons.
#
# ~/.onlyrc also allows to enable gradually more verbosity for denied
# commands.  Since this leaks information to an attacker it is also
# not recomended.  The configuration details are explained in the
# example .onlyrc file.
#
# The following example `authorized_keys` line shows how to allow to
# run the commands ls, who.
#
#     command="only ls who",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-rsa AAAA...
#
# A sample ~/.configrules file which locks down the commands to not
# allow any commandline parameters would look like this:
#
#     \:^ls$:{p;q}
#     \:^who$:{p;q}
#
# If the allowed command is specified with an absolute path, the
# requested command must be specified with exactly the same path.
#
#     command="only /bin/ls"
#
# Otherwise, if the requested command is specified with an absolute
# path it is only executed if it is on the users PATH, so we single
# out requests outside of the PATH - which you might restrict to
# something secure.
#
# There is a subtle difference between normal mode and command line
# substitution mode.  In normal mode the *original* command is run, so
# if you have e.g. `/bin/cmd` and `/usr/bin/cmd` and your PATH is:
# `/bin:/usr/bin` you can select to run on or the other by specifying
# the absolute path.  In substitution mode either the first command on
# the path is run (`/bin/cmd` in our example) or you must specify the
# absolute path in the allowed commands and adapte ~/onlyrules
# accordingly. 
#
# Command execution and denial is logged to the auth logging facility.
#
# Requirements: which (1), sed(1) and logger(1)

LOGGER=logger
SED=sed
WHICH=which
#
RULES=~/.onlyrules
RCFILE=~/.onlyrc

# check if rule file exit
if [ ! -f $RULES ]; then
    $LOGGER -p auth.warn -- no rules file $USER: $SSH_ORIGINAL_COMMAND
    exit 1
fi

# check if command substitution is allowed
if [ -f $RCFILE ]; then
    SUBST="$(sed -ne '/^enable_command_line_substitution$/p' $RCFILE)"
fi

# Test $SSH_ORIGINAL_COMMAND line against the rules file.  If it
# passes run it, else deny.
# The rule is selected via the $1 argument.
try () {
    allowed="$1"
    # strip off the command itself
    set -- $SSH_ORIGINAL_COMMAND
    original="$1"
    shift
    #
    CMD=$(echo "$allowed" $@ | $SED -nf $RULES)
    [ -z "$CMD" ] && deny 
    if [ -n "$SUBST" ]; then
	set -- $CMD
    else
	set -- $SSH_ORIGINAL_COMMAND
    fi
    $LOGGER -p auth.info -- running $USER: $@
    eval "$@"
    exit $?
}

# Deny the requested command more or less verbosely.
deny () {
    $LOGGER -p auth.warn -- denied $USER: $SSH_ORIGINAL_COMMAND
    if [ -f $RCFILE ]; then
	if [ -n "$(sed -ne '/^show_terse_denied/p' $RCFILE)" ]; then
	    echo denied >&2
	else
	    if [ -n "$(sed -ne '/^show_denied/p' $RCFILE)" ]; then
		echo denied: $SSH_ORIGINAL_COMMAND >&2
	    fi
	    if [ -n "$(sed -ne '/^show_allowed/p' $RCFILE)" ]; then
		echo allowed: $ALLOWED_COMMANDS
	    fi
	    if [ -n "$(sed -ne '/^help_text/p' $RCFILE)" ]; then
		sed -e '1,/^help_text/d' $RCFILE
	    fi
	fi
    fi
    exit 1
}

# main
ALLOWED_COMMANDS="$@"
set -- $SSH_ORIGINAL_COMMAND
for allowed in $ALLOWED_COMMANDS; do
    # If allowed starts with / we want exact match
    if [ x"${allowed%%/*}" = x ]; then
	if [ x"$allowed" = x"$1" ]; then
	    try $allowed
	else
	    continue
	fi
    fi

    # if original command starts with slash, we check if it is
    # in the path.
    if [ x"${1%%/*}" = x ]; then
	if [ x"$($WHICH $allowed)" = x"$1" ]; then
	    try $allowed
	else
	    continue
	fi
    fi
    # both are relative paths or filenames
    if [ x"$allowed" = x"$1" ]; then
	try $allowed
    fi
done

deny
