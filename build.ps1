# https://docs.microsoft.com/en-us/azure/devops/extend/develop/add-build-task?view=azure-devops

param(
    $localEnv = 'secrets.ps1',
    $root = $pwd
)

if($PSScriptRoot) {
    $root = $PSScriptRoot
}

if((test-path $root\$localEnv)) {
    . $root\$localEnv
    write-host "using vstsAccount:$vstsAccount"
}

write-host "cd $root\buildandreleasetask"
cd $root\buildandreleasetask
write-host "tsc"
tsc
write-host "cd $root"
cd $root
write-host "tfx extension create --manifest-globs vss-extension.json --rev-version"
tfx extension create --manifest-globs vss-extension.json --rev-version

$vsix = (resolve-path *.vsix).Path
# https://docs.microsoft.com/en-us/azure/devops/extend/publish/command-line?view=azure-devops
# tfx publish requires a pat with access to 'all organizations' which is not allowed on ms internal subs :|
write-host "tfx extension publish --manifest-globs vss-extension.json --vsix $vsix --share-with $vstsAccount --auth-type pat -t $vstsPat"
#tfx extension publish --manifest-globs vss-extension.json --vsix $vsix --share-with $vstsAccount --auth-type pat -t $vstsPat

# https://marketplace.visualstudio.com/manage/createpublisher?managePageRedirect=true
# https://marketplace.visualstudio.com/manage/publishers/jagilber

#[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\path\to\certificate.pfx"))
