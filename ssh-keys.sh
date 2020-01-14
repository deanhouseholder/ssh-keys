#!/bin/bash

#
# SSH Keys
# Description: Load ssh-agent and all of your ssh keys. Functions to generate new keys.
# Author: Dean Householder
# Version: 1.011
# Date: 2019-10-02
# Website: https://github.com/deanhouseholder/ssh-keys
#
#
# Example Usage:
#
# ssh_keys_load=(~/.ssh/id_rsa_personal ~/.ssh/id_rsa_work)
# ssh_keys_pass=(~/.ssh/.id_rsa_personal ~/.ssh/.id_rsa_work)
# source ~/bin/ssh-keys.sh
#



# Notes:
# Users can specify where they want to store each password file, but there should be a default format.
#  - Such as "in the same directory with a '.' prefix before the filename of the ssh key file."
#  - Example: If the key is 'id_rsa' then the password file would be '.id_rsa' or '.p-id_rsa'
#
# The "User Defined Preferences" are defaults that should be able to be overwritten if defined in
# their startup so they can leave this file unmodified.


##########################################
##       User Defined Preferences       ##
##########################################


# Define path to master salt file
master_salt_file=~/.ssh/.master

# Define a user-specific socket file
ssh_agent_socket=~/.ssh-agent-$UID.sock

# Quiet startup (default: errors_only)
# Options: info, quiet, errors_only
startup_output=errors_only


##########################################
##  You shouldn't need to modify below  ##
##########################################

alias keys='ssh-add -l'

# Help function
function ssh_keys_help {
  printf "help function\n"
  ## TODO: fill out this help section
  #   if you have a file already, here's how you define it.
  #   else prompt to record one
  #   else just default to manually entering each time they load the script

  # Create a new SSH Key via prompts
  # ssh-keys new key
  #
  # Create/Update a SSH Key password
  # ssh-keys add password
  #
  # Load ssh keys (shouldn't need to run this manually--just include keys.sh)
  # load_keys
}

# Check for defined array of ssh key files
if [[ -z "${ssh_keys_load[@]}" ]]; then
  printf "\nWarning: No ssh keys are defined.\n\n"
  printf "To define ssh keys create an array of file paths to ssh key files:\n"
  printf "ssh_keys_load=(~/.ssh/id_rsa_personal ~/.ssh/id_rsa_work)\n\n"
  printf "For a full list of options run:\nssh_key_help\n\n"
  return 1
fi


# API:
#
# Note: All options can have an optional equals sign
#
# -p, --path          [key_file_path]
# -t, --type          [type]
# -s, --size          [length]
# -i, --identifier    [email]
#
# ssh-keys help
# ssh-keys add key -p [key_file_path] -s [length] -t [type] -i [email]
# ssh-keys add securekey (or "both"?) -p [key_file_path] -s [length] -t [type] -i [email]
# ssh-keys add password [key_file_path]
# ssh-keys update password [key_file_path]
#
# function ssh-keys() {
#   if [[ "$1" -eq "add-key" ]]; then
#     echo 'hi'
#   fi
# }


# Count characters
function count_chars {
  echo "$1" | awk -F"$2" '{print NF-1}'
}

# Trim whitespace
function trim {
  echo "$1" | sed -e 's/^ *//' -e 's/ *$//'
}

# Show banner after key is created
function show_success_banner {
  key_path="$1"
  pw_path="$2"
  use_password="$3"
  printf "Success!\n\n"
  printf "Your new key files are:\n"
  printf "Private Key:         $key_path\n"
  printf "Public Key:          $key_path.pub\n"
  if [[ "$use_password" == "Y" ]]; then
    printf "Encrypted Password:  $pw_path\n\n"
  fi

  printf "\n#######################################################################\n\n"
  printf "To automatically add these keys into memory when you log into your\n"
  printf "terminal, you can add the following lines to your startup file:\n\n"
  printf "ssh_keys_load=($key_path)\n"
  if [[ "$use_password" == "Y" ]]; then
    printf "ssh_keys_pass=($pw_path)\n"
  fi
  printf "source /path/to/ssh-keys.sh\n"
  printf "\n#######################################################################\n\n"
}

# Convert relative paths into full paths and confirm the directories exist
function abs_dir_path() {
  local dir="$(trim "$1")"
  if [[ "${dir:0:1}" == "~" ]]; then
    cd ~ &>/dev/null
    local home="$PWD"
    cd - &>/dev/null
    dir="$home${dir:1}"
  fi
  local depth="$(count_chars "$dir" "/")"
  if [[ "$depth" == "0" ]]; then
    dir="$PWD/$dir"
  elif [[ "$depth" == "1" ]]; then
    dir="/"
  fi
  if [[ ! -d "$dir" ]]; then
    dir="$(echo $dir | sed -r 's/(.*)\/.*/\1/')"
  fi
  cd "$dir" &>/dev/null
  if [[ $? != "0" ]]; then
    return 1
  fi
  echo "$PWD"
  cd - &>/dev/null
}

# $1 = key file name (optional)
function keys_loaded_count {
  echo "$(ssh-add -l | grep "$1 "'(' | wc -l | awk '{print $1}')"
}

# $1 = Path to key file
function check_if_pw_required {
  ssh-keygen -y -P "" -f "$1" &>/dev/null
  test $? -eq 0 && echo 0 || echo 1
}

# $1 = Path to key file
# $2 = PW
function check_if_pw_unlocks_key {
  ssh-keygen -y -P "$2" -f "$1" &>/dev/null
  test $? -eq 0 && echo 0 || echo 1
}

# $1 = Plain-text String
function encrypt_key {
  echo "$1" | openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 10000 -a -salt -pass file:"$master_salt_file"
}

# $1 = Encrypted String
function decrypt_key {
  echo "$1" | openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 10000 -a -salt -pass file:"$master_salt_file" -d
}

# Generate a ssh key
# $1 = Type of key to generate (rsa, dsa, ecdsa, ed25519)
# $2 = Size of key in bytes (2048, 4096, 6144, 8192)
# $3 = Path to file to be created
# $4 = Path to password file to be created
# $5 = Email address for key identification
function generate_ssh_key {
  local type="$1"
  local size="$2"
  local key_path="$3"
  local pw_path="$4"
  local email="$5"
  local epass="$(cat $pw_path)"
  local pass="$(decrypt_key "$epass")"
  printf "\nType: $type\nSize: $size\nKey Path: $key_path\nPW Path: $pw_path\nE-Pass: $epass\nPass: $pass\nEmail: $email\n\n"
  ssh-keygen -f "$key_path" -t "$type" -b "$size" -N "$pass" -C "$email"
}

# Write an encrypted key file
function create_encrypted_key_file {
  local pw="$1"
  local file="$2"
  local ekey=$(encrypt_key "$pw")
  echo "$ekey" > $file
  local status=$?
  chmod 600 $file
  if [[ $status -eq 0 ]]; then
    return 0
  else
    return 1
  fi
}

# This function will clear and set global variables for the various parts of a path
function path_get_parts {
  unset  _path _dir _file _file_exists _writable _path_valid
  export _path _dir _file _file_exists _writable _path_valid
  _path_valid=0
  _path="$(trim "$1")"
  _dir="$(abs_dir_path "$_path")"
  test $? == "1" && _path_valid=0
  _file="$(echo $_path | sed -r 's/.*\/(.*)/\1/')"
  test "$_dir" != "/" && _path="$_dir/$_file" || _path="/$_file"
  test -d "$_dir" && _path_valid=1
  test -f "$_path" && _file_exists=1 || _file_exists=0
  if [[ "$_file_exists" == "0" ]]; then
    touch "$_path" 2>/dev/null
    test $? -eq 0 && _writable=1 || _writable=0
    # Delete the newly created file if it is 0 bytes
    find "$_dir" -maxdepth 1 -name "$_file" -empty -ctime 0 -delete 2>/dev/null
  fi
  #printf "\n_dir: $_dir\n_file: $_file\n_path: $_path\n_file_exists: $_file_exists\n"
  #printf "_path_valid: $_path_valid\n_writable: $_writable\n\n"
  return 1
}

# Prompt for a password
function add_password {
  local dir="$1"
  local file="$2"
  local pass char prompt
  export pw_path

  # Capture Password
  printf "\nEnter the password you would like to use: "
  unset pass
  while IFS= read -p "$prompt" -r -s -n 1 char
  do
    if [[ $char == $'\0' ]]; then
        break
    elif [[ $char == $'\177' ]]; then
        prompt=$'\b \b'
        pass="${pass%?}"
    else
      prompt='*'
      pass+="$char"
    fi
  done

  # Capture path to PW file
  pw_path_valid=0
  if [[ ! -z "$dir" ]] && [[ ! -z "$file" ]]; then
    default_pw_path="$dir/.$file"
    local display_string="(Default is: $default_pw_path)"
  else
    default_pw_path=""
    local display_string=""
  fi
  printf "\n\nWhere would you like to save your encrypted password file?\n$display_string "
  read pw_path
  test -z "$pw_path" && pw_path="$default_pw_path"
  path_get_parts "$pw_path"
  pw_path="$_path"
  pw_dir="$_dir"
  pw_file="$_file"
  if [[ "$_path_valid" == "1" ]] && [[ "$_writable" == "1" ]]; then
    printf "\nYou entered: $pw_path\n"
  elif [[ "$_file_exists" == "1" ]]; then
    printf "\nError: That file already exists!\n"
    printf "Please choose a different filename.\n\n"
    return 1
  elif [[ "$_path_valid" == "1" ]] && [[ "$_writable" == "0" ]]; then
    printf "\nError: The path you selected is not writable by your user account.\n\n"
    return 1
  else
    printf "\nError: The path you selected is invalid.\n\n"
    return 1
  fi

  # Write encrypted password file
  printf "\n\nGenerating password file... "
  create_encrypted_key_file "$pass" "$pw_path"
  if [[ $? -eq 0 ]]; then
    show_success_banner "$key_path" "$pw_path" "Y"
    return 0
  else
    return 1
  fi
}

# Create a new ssh key
function create_ssh_key {
  local type size sizes default_size size_valid sizes_string
  local key_path_valid key_path dir file file_already_exists writable
  local email default_email email_string use_password

  printf "\nSSH Key Creator\n"

  # Get the type of key
  printf "\nWhat type of SSH key would you like to create? [RSA, DSA, ECDSA] (Default is: RSA) "
  read type
  type="$(echo "$type" | tr a-z A-Z)"
  if [[ -z "$type" ]] || [[ "$type" =~ E?C?[RD][S][A] ]]; then
    test -z "$type" && type="RSA"
    printf "You selected $type\n"
  else
    printf "\nError: you must enter either RSA or DSA\n\n"
    return 1
  fi

  # Get the size of key
  case $type in
  "RSA")
    sizes=(2048 4096 8192)
    default_size=8192
    ;;
  "DSA")
    sizes=(1024)
    default_size=1024
    ;;
  "ECDSA")
    sizes=(256 384 521)
    default_size=256
    ;;
  esac

  size_valid=0
  sizes_string=""
  for i in ${!sizes[@]}; do
    test $i -gt 0 && sizes_string+=", "
    sizes_string+="${sizes[$i]}"
  done

  printf "\nWhat size of key would you like to create? [$sizes_string] (Default is: $default_size) "
  read size
  test -z "$size" && size=$default_size
  size="$(trim "$size")"
  for i in ${!sizes[@]}; do
    test "$size" == "${sizes[$i]}" && size_valid=1
  done
  if [[ "$size_valid" != "1" ]]; then
    printf "\nError: $size is not a valid option.\nValid options are: $sizes_string\n\n"
    return 1
  fi
  printf "You selected $size bits\n"

  # Get the path to the key file
  printf "\nWhere would you like to save your key? (Default is: ~/.ssh/id_rsa) "
  read key_path

  path_get_parts "$key_path"
  key_path="$_path"
  dir="$_dir"
  file="$_file"

  if [[ "$_path_valid" == "1" ]] && [[ "$_writable" == "1" ]]; then
    printf "You selected: $key_path\n"
  elif [[ "$_file_exists" == "1" ]]; then
    printf "\nError: That file already exists!\n\n"
    printf "Please choose a different filename.\n\n"
    return 1
  elif [[ "$_path_valid" == "1" ]] && [[ "$_writable" == "0" ]]; then
    printf "\nError: The path you selected is not writable by your user account.\n\n"
    return 1
  else
    printf "\nError: The path you selected is invalid.\n\n"
    return 1
  fi

  # Get the email address to use in the key comments
  default_email="$(git config --global user.email)"
  if [[ ! -z "$default_email" ]]; then
    email_string="\n(Default is: $default_email)"
  fi
  printf "\nWhat is your email address (to be added to the comments in the key)? $email_string "
  read email
  email="$(trim "$email")"
  test -z "$email" && email="$default_email"
  if [[ -z "$type" ]]; then
    printf "\nError: you must enter your email address.n\n"
    return 1
  else
    printf "You entered: $email\n"
  fi

  printf "\nWould you like to add a password? [Y/N] (Default is: Y) "
  read use_password
  test -z "$use_password" && use_password="Y"
  use_password="$(echo "$use_password" | tr a-z A-Z)"
  use_password="$(trim "$use_password")"
  use_password="${use_password:0:1}"
  if [[ ! "$use_password" =~ [YN] ]]; then
    printf "\nError: you must enter either Y or N\n\n"
    return 1
  fi

  if [[ "$use_password" == "Y" ]]; then
    add_password "$dir" "$file"
  else
    # Skip password
    printf "\nSkipping password\n"
  fi

  printf "\n\nGenerating new SSH key... "

  # Generate SSH Key
  generate_ssh_key "$type" "$size" "$key_path" "$pw_path" "$email" >/dev/null

  if [[ $? -eq 0 ]]; then
    show_success_banner "$key_path" "$pw_path" "$use_password"
  else
    printf "\nKey generation failed.\n"
  fi

  printf "\n"
  return 0
}

# Create and store an encrypted password file for a ssh key
function ssh_keys_password {
  local dir file key_path pw_path

  printf "\nSSH Key Password Creator\n\n"

  # Get the path to the existing SSH key
  printf "What is the path to your ssh key? (Should be one which requires a password)\n"
  read key_path
  if [[ -z "$(trim $key_path)" ]]; then
    printf "Error: You must specify a path.\n\n"
    return 1
  fi
  path_get_parts "$key_path"
  key_path="$_path"
  if [[ "$_path_valid" == "0" ]]; then
    printf "\nError: The path you selected is invalid.\n\n"
    return 1
  fi
  printf "\nYou entered: $key_path\n"

  add_password "$_dir" "$_file"
  if [[ $? -ne 0 ]]; then
    printf "Failed to create your encrypted password file\n"
  fi

  ## TODO: This could test to see if the key actually unlocks the key

  printf "\n\n"
}

# Start the ssh-agent daemon if is not running
function start_agent {
  ssh_cmd="ssh-agent -a $ssh_agent_socket -s"

  # Delete the socket file if ssh-agent is not running
  running_agents=$(ps -x | grep "$ssh_cmd" | grep -v grep | wc -l)
  if [[ -S $ssh_agent_socket ]] && [[ $running_agents -eq 0 ]]; then
    rm $ssh_agent_socket
  fi

  # Start the agent if it is not running
  if [[ $running_agents -eq 0 ]]; then
    $ssh_cmd >/dev/null 2>&1
  fi
  eval "export SSH_AUTH_SOCK=$ssh_agent_socket"
}

# Add keys into ssh-agent based on $ssh_keys_load and $ssh_keys_pass arrays
# Note: Output can be controlled with either: info, quiet, or errors_only
function load_keys {
  local out errors status key_file key_pw_file tmp_pw_file pw_required sep
  sep='ᚦ' # Obscure ascii character not likely to appear in filenames

  # Loop through each key
  for i in ${!ssh_keys_load[@]}; do
    key_file=${ssh_keys_load[$i]}
    key_pw_file=${ssh_keys_pass[$i]}

    # Check if the key file exists
    if [[ -f $key_file ]]; then

      # Check if the key is already loaded
      if [[ "$(keys_loaded_count $key_file)" == "0" ]]; then

        # Determine if they key needs a password
        pw_required=$(check_if_pw_required $key_file)
        if [[ $pw_required -eq 1 ]]; then

          # Check if the key password file exists
          if [[ -f $key_pw_file ]]; then

            # Use the key file to add the ssh key
            tmp_pw_file=~/.tmp_key_pw_file
            echo "echo \"$(decrypt_key "$(cat $key_pw_file)")\"" > $tmp_pw_file
            chmod 700 $tmp_pw_file
            cat $key_file | SSH_ASKPASS=$tmp_pw_file DISPLAY= ssh-add $key_file 2>/dev/null
            status=$?
            rm $tmp_pw_file

            # If it failed to add, the password must be bad
            if [[ $status != "0" ]]; then
              errors+="Error: Bad password for $key_file.\n"
            fi
          else
            status=1
            errors+="Error: No password file defined for $key_file.\n"
          fi

        else
          # Add the ssh key without a password
          ssh-add $key_file 2>/dev/null
          status=$?
        fi

        if [[ $status == "0" ]]; then
          out+="Adding key: $key_file${sep}\e[32m[Success]\e[0m\n"
        else
          out+="Adding key: $key_file${sep}\e[31m[Fail]\e[0m\n"
        fi

      else
        out+="Adding key: $key_file${sep}\e[32m[Already Loaded]\e[0m\n"
      fi

    else
      errors+="Error: SSH key file not found: $key_file\n"
    fi

    unset status
  done

  if [[ "$1" == "info" ]]; then
    printf "$out" | column -s "$sep" -t
  fi
  if [[ ! -z "$errors" ]] && [[ "$1" != "quiet" ]]; then
    printf "\n$errors"
    printf "\nFor help, run:  ssh_key_help\n\n"
  fi
}

# Generate a new random master key if not found
if [[ ! -f $master_salt_file ]]; then
  openssl rand -hex 30 > $master_salt_file
  chmod 400 $master_salt_file
fi

# Start ssh-agent if it is not running
start_agent

# Load keys
load_keys $startup_output
