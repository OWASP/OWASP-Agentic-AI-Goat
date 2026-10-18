'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const path=require('node:path');
const fs=require('node:fs');
const os=require('node:os');
for(const platform of ['linux','macos'])for(const present of [true,false])test(`${platform} Compose prerequisite ${present?'reuses available command':'installs missing command'}`,t=>{
  const file=path.resolve(__dirname,`../scripts/install/${platform}-prerequisites.sh`);
  // Exercise real plugin discovery/linking only inside disposable directories.
  // A successful package-manager command alone is not Compose v2 readiness.
  const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-compose-prerequisite-'));
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
  [ "$*" = "compose version" ] || return 1
  [ "$installed" = 1 ] || [ -x "$DOCKER_CONFIG/cli-plugins/docker-compose" ]
}
docker-compose() { return 1; }
apt-cache() { [ "$2" = docker-compose-v2 ]; }
apt-get() { echo "installed:$*"; installed=1; }
as_root() { "$@"; }
brew() {
  case "$*" in
    'list --formula docker-compose') [ -x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose" ] ;;
    '--prefix') printf '%s\\n' "$FAKE_BREW_PREFIX" ;;
    'install docker-compose')
      echo "installed:$*"
      mkdir -p "$FAKE_BREW_PREFIX/lib/docker/cli-plugins"
      printf '#!/bin/sh\\nexit 0\\n' > "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose"
      chmod +x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose" ;;
    *) return 1 ;;
  esac
}
ensure_${platform}_compose
`;
  const result=spawnSync('bash',['-c',script,'compose-test',file,path.resolve(__dirname,'..')],{
    encoding:'utf8',env:{...process.env,DOCKER_CONFIG:dockerConfig,FAKE_BREW_PREFIX:path.join(fixture,'brew')},
  });
  assert.equal(result.status,0,result.stderr);
  if(present)assert.equal(result.stdout,'');else assert.match(result.stdout,platform==='linux'?/installed:install -y --no-install-recommends docker-compose-v2/:/installed:install docker-compose/);
  assert.equal(fs.readFileSync(path.join(dockerConfig,'config.json'),'utf8'),config);
  const plugin=path.join(dockerConfig,'cli-plugins/docker-compose');
  if(platform==='macos'&&!present){
    assert.equal(fs.lstatSync(plugin).isSymbolicLink(),true);
    assert.equal(fs.readlinkSync(plugin),path.join(fixture,'brew/lib/docker/cli-plugins/docker-compose'));
  }else assert.equal(fs.existsSync(plugin),false);
});
