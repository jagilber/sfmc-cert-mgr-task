# https://docs.microsoft.com/en-us/azure/devops/extend/develop/add-build-task?view=azure-devops

param(
    $vstsAccount = 'jagilber@microsoft.com'
)
$root = $pwd
if($PSScriptRoot) {
    $root = $PSScriptRoot
}

write-host "cd $root\buildandreleasetask"
cd $root\buildandreleasetask
write-host "tsc"
tsc
write-host "cd $root"
cd $root
write-host "tfx extension create --manifest-globs vss-extension.json"
tfx extension create --manifest-globs vss-extension.json

$vsix = (resolve-path *.vsix).Path

write-host "tfx extension publish --manifest-globs vss-extension.json --vsix $vsix --share-with $vstsAccount"
tfx extension publish --manifest-globs vss-extension.json --vsix $vsix --share-with $vstsAccount

# https://marketplace.visualstudio.com/manage/createpublisher?managePageRedirect=true
# https://marketplace.visualstudio.com/manage/publishers/jagilber

#[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\path\to\certificate.pfx"))
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\temp\sfjagilber-sfjagilber-20220525.pfx"))