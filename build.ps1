# https://docs.microsoft.com/en-us/azure/devops/extend/develop/add-build-task?view=azure-devops
write-host "cd .\buildandreleasetask"
cd .\buildandreleasetask
write-host "tsc"
tsc
write-host "cd .."
cd ..
write-host "tfx extension create --manifest-globs vss-extension.json"
tfx extension create --manifest-globs vss-extension.json

# https://marketplace.visualstudio.com/manage/createpublisher?managePageRedirect=true
# https://marketplace.visualstudio.com/manage/publishers/jagilber

#[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\path\to\certificate.pfx"))
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\temp\sfjagilber-sfjagilber-20220525.pfx"))