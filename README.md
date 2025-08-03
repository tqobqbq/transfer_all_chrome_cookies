# transfer_all_chrome_cookies
Convert the cookies file to transfer all chrome cookies to another computer's chrome

Most of codes about v20 key are from https://github.com/runassu/chrome_v20_decryption   and v10 from https://stackoverflow.com/questions/78482316/decrypt-re-encrypt-chrome-cookies

Remember to backup the cookies file!

step 1:

On the source computer,run the function run_for_source_chrome() to get the v10 and v20 master keys

step 2:

On the target computer,backup the cookies file,fill in the master keys from step1 to the function run_for_target_chrome and run it to convert the cookies file

step 3:

Copy the converted cookies file to the chrome's data folder(by default at:"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies")
