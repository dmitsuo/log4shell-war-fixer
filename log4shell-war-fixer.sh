#!/bin/bash

set -x

LOG4J_FILE_PATTERN=log4j-core-
JAR_FOLDER=WEB-INF/lib
LOG4J_WAR_FILEPATH=${JAR_FOLDER}/${LOG4J_FILE_PATTERN}
JNDILOOKUP_CLASS_PATH=org/apache/logging/log4j/core/lookup/JndiLookup.class

if [ $# -eq 0 ]
then
    echo "ERROR: Filename is missing!"
	exit 1
fi

WAR_FILE="$1"
LOWERCASE_WAR_FILE="${WAR_FILE,,}"

if [[ ! ${LOWERCASE_WAR_FILE} =~ \.war$ ]]; then
    echo "ERROR: Filename is not a WAR!"
    exit 1
fi

strings "${WAR_FILE}" | grep "${LOG4J_FILE_PATTERN}" > /dev/null
if [ $? -eq 0 ]; then
    echo "Log4J v2.x found!"

    echo "Extracting Log4J from WAR file..."
    unzip -o "${WAR_FILE}" "${LOG4J_WAR_FILEPATH}*" -d .

    LOG4J_FILEPATH=$(ls ${LOG4J_WAR_FILEPATH}*.jar)
    
    strings "${LOG4J_FILEPATH}" | grep "${JNDILOOKUP_CLASS_PATH}" > /dev/null
    if [ $? -eq 0 ]; then
        echo "Removing JndiLookup.class from Log4J..."
        zip -q -d "${LOG4J_FILEPATH}" "${JNDILOOKUP_CLASS_PATH}"

        echo "Backing up original WAR file..."
        cp -p "${WAR_FILE}" "${WAR_FILE}.bak"
        
        echo "Replacing patched Log4J inside WAR..."
        zip "${WAR_FILE}" "${LOG4J_FILEPATH}"
    else
        echo "JNDI lookup class not found. Nothing to do."
    fi    

    #echo "Cleaning up..."
    #rm -rdf "${JAR_FOLDER}"

else
    echo "Log4J v2.x not found. Nothing to do."    

fi