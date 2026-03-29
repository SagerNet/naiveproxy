#!/bin/sh
set -ex
have_version=$(cut -d= -f2 src/chrome/VERSION | tr '\n' . | cut -d. -f1-4)
want_version=$(cat CHROMIUM_VERSION)
if [ "$have_version" = "$want_version" ]; then
  exit 0
fi
name="chromium-$want_version"
tarball="$name.tar.xz"
url="https://commondatastorage.googleapis.com/chromium-browser-official/$tarball"
root=$(git rev-list --max-parents=0 HEAD)
branch=$(git branch --show-current)
git config core.autocrlf false
git config core.safecrlf false
git -c advice.detachedHead=false checkout $root
rm -rf src
git checkout "$branch" -- tools
sed -i "s/^\^/$name\//" tools/include.txt
if [ -f "/tmp/$tarball" ]; then
  cat "/tmp/$tarball" | tar xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
else
  curl "$url" -o- | tar xJf - --wildcards --wildcards-match-slash -T tools/include.txt -X tools/exclude.txt
fi
mv "$name" src
for component in cronet prefs; do
  component_url="https://chromium.googlesource.com/chromium/src/+archive/refs/tags/$want_version/components/$component.tar.gz"
  mkdir -p "src/components/$component"
  curl -sL "$component_url" | tar xzf - -C "src/components/$component"
done
git rm --quiet --force -r tools
git add src
git commit --quiet --amend -m "Import $name" --date=now
echo "Import done. Root commit amended. Run rebase manually:"
echo "  git rebase --onto HEAD $root $branch"
