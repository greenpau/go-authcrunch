#!/bin/bash
set -e

printf "Updating UI apps\n"

SCRIPT_DIR=$(cd -P -- "$(dirname -- "$0")" && printf '%s\n' "$(pwd -P)")
ASSETS_DIR=$(dirname -- "$SCRIPT_DIR")
ROOT_DIR=$(dirname -- "$ASSETS_DIR")

echo $SCRIPT_DIR
echo $ROOT_DIR


UI_FILE=pkg/authn/ui/apps.go

declare -a _APPS
_APPS[${#_APPS[@]}]="profile"

cat << 'EOF' > ${UI_FILE}
package ui

import (
	"embed"
)

var (
    //go:embed profile
    embedFileSystem embed.FS
    embedPages = map[string]string{
EOF

for APP_ID in "${!_APPS[@]}"; do
    cd $ROOT_DIR
    APP_NAME=${_APPS[$APP_ID]};
    echo "Updating ${APP_NAME} app";
    APP_DIR=../../authcrunch/authcrunch-ui/frontend/${APP_NAME}/build
    if [ -d ${APP_DIR} ]; then
        echo "App directory ${APP_DIR} exists."
    else
        echo "ERROR: App directory ${APP_DIR} does not exist."
        exit 1
    fi
    rm -rf pkg/authn/ui/${APP_NAME}
    cp -R ../../authcrunch/authcrunch-ui/frontend/${APP_NAME}/build pkg/authn/ui/${APP_NAME}
    echo "\"${APP_NAME}/\": \"${APP_NAME}/index.html\"," >> ${UI_FILE}

    cd pkg/authn/ui
    for APP_UI_FILE in `find ${APP_NAME} -type f`; do
        echo "\"${APP_UI_FILE}\": \"${APP_UI_FILE}\"," >> apps.go
    done
    cd $ROOT_DIR
done


cat << 'EOF' >> ${UI_FILE}
    }
)
EOF
go fmt ${UI_FILE}