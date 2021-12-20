#!/bin/bash

#set -x

LOG4J_FILE_PATTERN=log4j-core-
JAR_FOLDER=WEB-INF/lib
LOG4J_WAR_FILEPATH=${JAR_FOLDER}/${LOG4J_FILE_PATTERN}
JNDILOOKUP_CLASS_PATH=org/apache/logging/log4j/core/lookup/JndiLookup.class

if ! [ -x "$(command -v zip)" ]; then
    echo "ERROR: \"zip\" command not found! You need to install \"zip\" in order to run this program."
    exit 1
fi

if ! [ -x "$(command -v unzip)" ]; then
    echo "ERROR: \"unzip\" command not found! You need to install \"unzip\" in order to run this program."
    exit 1
fi

if [ $# -eq 0 ]
then
    echo "ERROR: Filename is missing!"
	exit 1
fi

WAR_FILE="$1"
LOWERCASE_WAR_FILE="${WAR_FILE,,}"

if [[ ! ${LOWERCASE_WAR_FILE} =~ \.war$ ]]; then
    echo "ERROR: \"${WAR_FILE}\" is not a WAR file!"
    exit 1
fi

if [ ! -f "${WAR_FILE}" ]; then	
	echo "ERROR: \"${WAR_FILE}\" not found!"
    exit 1
fi

echo "Checking \"${WAR_FILE}\"..."

strings "${WAR_FILE}" | grep "${LOG4J_FILE_PATTERN}" > /dev/null
if [ $? -eq 0 ]; then
    echo "Log4J v2.x found!"

    echo "Extracting Log4J file from WAR file..."
    unzip -o "${WAR_FILE}" "${LOG4J_WAR_FILEPATH}*" -d .

    LOG4J_FILEPATH=$(ls ${LOG4J_WAR_FILEPATH}*.jar)
    
    strings "${LOG4J_FILEPATH}" | grep "${JNDILOOKUP_CLASS_PATH}" > /dev/null
    if [ $? -eq 0 ]; then
        echo "Removing \"JndiLookup.class\" file from Log4J..."
        zip -q -d "${LOG4J_FILEPATH}" "${JNDILOOKUP_CLASS_PATH}"

        echo "Backing up original WAR file..."
        cp -fp "${WAR_FILE}" "${WAR_FILE}.bak"
        
        echo "Replacing patched Log4J file inside WAR..."
        zip -q "${WAR_FILE}" "${LOG4J_FILEPATH}"

        echo "\"${WAR_FILE}\" successfully patched!"
    else
        echo "\"JndiLookup.class\" file not found. Nothing to do."
    fi    

    #echo "Cleaning up..."
    #rm -rdf "${JAR_FOLDER}"

else
    echo "Log4J v2.x not found. Nothing to do."    

fi