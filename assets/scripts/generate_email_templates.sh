#!/bin/bash
set -e

printf "Generating default email messaging templates\n"

TMPL_BODY_FILE=pkg/messaging/email_template_body.go
TMPL_SUBJ_FILE=pkg/messaging/email_template_subject.go

declare -a _LANG
declare -a _TEMPLATES
declare -a _NAMES
_LANG[${#_LANG[@]}]="en"
_TEMPLATES[${#_TEMPLATES[@]}]="registration_confirmation"
_TEMPLATES[${#_TEMPLATES[@]}]="registration_ready"
_TEMPLATES[${#_TEMPLATES[@]}]="registration_verdict"

printf "package messaging\n\n" > ${TMPL_BODY_FILE}
printf "// EmailTemplateBody stores email body templates.\n" >> ${TMPL_BODY_FILE}
printf "var EmailTemplateBody = map[string]string{\n" >> ${TMPL_BODY_FILE}

printf "package messaging\n\n" > ${TMPL_SUBJ_FILE}
printf "// EmailTemplateSubject stores email subject templates.\n" >> ${TMPL_SUBJ_FILE}
printf "var EmailTemplateSubject = map[string]string{\n" >> ${TMPL_SUBJ_FILE}

for LANG_ID in "${!_LANG[@]}"; do
    LANG_NAME=${_LANG[$LANG_ID]};
    echo "Generating theme ${LANG_NAME}";
    for TMPL_ID in "${!_TEMPLATES[@]}"; do
        TMPL_NAME=${_TEMPLATES[$TMPL_ID]};
        echo "At template ${TMPL_NAME}";

        # Email body
        printf "\"${LANG_NAME}/${TMPL_NAME}\": \`" >> ${TMPL_BODY_FILE}
        cat assets/portal/messaging/templates/email/${LANG_NAME}/${TMPL_NAME}_body.template >> ${TMPL_BODY_FILE}
        truncate -s -1 ${TMPL_BODY_FILE}
        printf "\`,\n" >> ${TMPL_BODY_FILE}

        # Email subject.
        printf "\"${LANG_NAME}/${TMPL_NAME}\": \`" >> ${TMPL_SUBJ_FILE}
        cat assets/portal/messaging/templates/email/${LANG_NAME}/${TMPL_NAME}_subject.template >> ${TMPL_SUBJ_FILE}
        truncate -s -1 ${TMPL_SUBJ_FILE}
        printf "\`,\n" >> ${TMPL_SUBJ_FILE}

    done
done

printf "}\n" >> ${TMPL_BODY_FILE}
go fmt ${TMPL_BODY_FILE}
versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=${TMPL_BODY_FILE}

printf "}\n" >> ${TMPL_SUBJ_FILE}
go fmt ${TMPL_SUBJ_FILE}
versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=${TMPL_SUBJ_FILE}
