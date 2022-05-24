# https://docs.microsoft.com/en-us/azure/devops/extend/develop/add-build-task?view=azure-devops
cd .\buildandreleasetask
tsc
cd ..
tfx extension create --manifest-globs vss-extension.json

# https://marketplace.visualstudio.com/manage/createpublisher?managePageRedirect=true