#!/bin/bash

javac -d bin src/com/maxoflondon/ossutils/traptester/*.java
if [ $? != 0 ]; then return; fi
echo Compiled ok.
#cp src/com/maxoflondon/ossutils/traptester/*.properties bin/com/colt/ossutils/smartsmodelvalidator/
jar cfm trapsim.jar META-INF/MANIFEST.MF  -C bin com/maxoflondon/ossutils/traptester/
if [ $? != 0 ]; then return; fi
echo JARed ok.
if [ "$#" -ne 1 ]; then
	rm -f bin/com/maxoflondon/ossutils/traptester/*
	if [ $? != 0 ]; then return; fi
	echo bin files deleted ok.
fi