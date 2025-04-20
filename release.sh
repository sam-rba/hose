version=$(git describe --tags --abbrev=0)

gooses=(darwin linux windows)
goarches=(amd64 arm64)

if [ ! -d bin ]; then
	mkdir bin
fi

for goos in "${gooses[@]}"; do
	for goarch in "${goarches[@]}"; do
		file="hose_${version}_${goos}_${goarch}"
		if [ "$goos" = "windows" ]; then
			file="$file.exe"
		fi
		echo $file
		GOOS=$goos GOARCH=$goarch go build -o "bin/$file"
	done
done

echo done
