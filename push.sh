# Push to github by kanha
echo "Commit Message?"

read message

git add .

git commit -am "$message"

git push origin main