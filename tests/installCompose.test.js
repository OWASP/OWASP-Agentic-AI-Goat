'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const path=require('node:path');
const fs=require('node:fs');
const os=require('node:os');
for(const plugin of ['compose','buildx'])for(const platform of ['linux','macos'])for(const present of [true,false])test(`${platform} ${plugin} prerequisite ${present?'reuses available command':'installs missing command'}`,t=>{
  const file=path.resolve(__dirname,`../scripts/install/${platform}-prerequisites.sh`);
  // Exercise real plugin discovery/linking only inside disposable directories.
  // A successful package-manager command alone is not Compose v2 readiness.
  const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-compose-prerequisite-'));
  t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
  const dockerConfig=path.join(fixture,'docker-config');
  fs.mkdirSync(dockerConfig);
  const config='{"currentContext":"preserved-fixture"}\n';
  fs.writeFileSync(path.join(dockerConfig,'config.json'),config);
  const script=`set -euo pipefail
ROOT="$2"
source "$1"
installed=${present?'1':'0'}
die() { echo "$*" >&2; exit 1; }
docker() {
  [ "$*" = "${plugin} version" ] || return 1
  [ "$installed" = 1 ] || [ -x "$DOCKER_CONFIG/cli-plugins/docker-${plugin}" ]
}
docker-compose() { return 1; }
apt-cache() { [ "$2" = docker-${plugin==='compose'?'compose-v2':'buildx'} ]; }
apt-get() { echo "installed:$*"; installed=1; }
as_root() { "$@"; }
brew() {
  case "$*" in
    'list --formula docker-${plugin}') [ -x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-${plugin}" ] ;;
    '--prefix') printf '%s\\n' "$FAKE_BREW_PREFIX" ;;
    'install docker-${plugin}')
      echo "installed:$*"
      mkdir -p "$FAKE_BREW_PREFIX/lib/docker/cli-plugins"
      printf '#!/bin/sh\\nexit 0\\n' > "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-${plugin}"
      chmod +x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-${plugin}" ;;
    *) return 1 ;;
  esac
}
ensure_${platform}_${plugin}
`;
  const result=spawnSync('bash',['-c',script,'compose-test',file,path.resolve(__dirname,'..')],{
    encoding:'utf8',env:{...process.env,DOCKER_CONFIG:dockerConfig,FAKE_BREW_PREFIX:path.join(fixture,'brew')},
  });
  assert.equal(result.status,0,result.stderr);
  if(present)assert.equal(result.stdout,'');else assert.match(result.stdout,new RegExp(platform==='linux'?`installed:install -y --no-install-recommends docker-${plugin==='compose'?'compose-v2':'buildx'}`:`installed:install docker-${plugin}`));
  assert.equal(fs.readFileSync(path.join(dockerConfig,'config.json'),'utf8'),config);
  const pluginPath=path.join(dockerConfig,`cli-plugins/docker-${plugin}`);
  if(platform==='macos'&&!present){
    assert.equal(fs.lstatSync(pluginPath).isSymbolicLink(),true);
    assert.equal(fs.readlinkSync(pluginPath),path.join(fixture,`brew/lib/docker/cli-plugins/docker-${plugin}`));
  }else assert.equal(fs.existsSync(pluginPath),false);
});

for(const repair of [false,true])test(`macOS daemon readiness keeps ${repair?'repair authority':'selected fresh profile'}`,()=>{
  const result=spawnSync('bash',['-c',`set -euo pipefail
source "$1"
die() { echo "$*" >&2; exit 1; }
docker() { echo "probe:$*" >&2; return 1; }
sleep() { :; }
colima() { echo unexpected-start >&2; exit 9; }
open() { echo unexpected-desktop >&2; exit 9; }
ensure_macos_docker_ready ${repair} colima-owned
`,'daemon-test',path.resolve(__dirname,'../scripts/install/macos-prerequisites.sh')],{encoding:'utf8',env:process.env});
  assert.equal(result.status,1);
  assert.doesNotMatch(result.stderr,/unexpected-/);
  const probes=result.stderr.split('\n').filter(line=>line.startsWith('probe:'));
  // Probe stderr is deliberately suppressed by the real helper.
  assert.equal(probes.length,0);
  assert.match(result.stderr,repair?/previously bound/:/selected Colima/);
});

for(const repair of [false,true])test(`macOS ready daemon uses exact ${repair?'existing selection':'Colima context'}`,()=>{
  const result=spawnSync('bash',['-c',`set -euo pipefail
source "$1"
die() { echo "$*" >&2; exit 1; }
docker() { [ "$*" = "${repair?'info':'--context colima-owned info'}" ]; }
sleep() { :; }
ensure_macos_docker_ready ${repair} colima-owned
`,'daemon-test',path.resolve(__dirname,'../scripts/install/macos-prerequisites.sh')],{encoding:'utf8',env:process.env});
  assert.equal(result.status,0,result.stderr);
});

test('Linux Buildx package success without usable plugin fails readiness',()=>{
  const result=spawnSync('bash',['-c',`set -euo pipefail
ROOT="$2"
source "$1"
die() { echo "$*" >&2; exit 1; }
docker() { return 1; }
apt-cache() { [ "$2" = docker-buildx-plugin ]; }
as_root() { echo "$*"; }
ensure_linux_buildx
`,'buildx-test',path.resolve(__dirname,'../scripts/install/linux-prerequisites.sh'),path.resolve(__dirname,'..')],{encoding:'utf8',env:process.env});
  assert.equal(result.status,1);
  assert.match(result.stdout,/apt-get install -y --no-install-recommends docker-buildx-plugin/);
  assert.match(result.stderr,/did not provide/);
});
