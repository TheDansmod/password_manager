import json
import secrets
import pyperclip as pc
from rich.console import Console
from rich.markup import escape
import random
import string
from rich.prompt import Prompt
from rich.prompt import IntPrompt
import getpass
import base64
import gnupg
import os
from datetime import datetime, timezone

console = Console()


class Config:
    def __init__(self):
        self.access_password = getpass.getpass("Enter password (Remember it, since all the data is lost without it): ")
        self.pwd_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/encrypted_passwords.enc"
        self.first_names_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/first_names.txt"
        self.last_names_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/last_names.txt"
        self.adjectives_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/adjectives.txt"
        self.common_nouns_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/common_nouns.txt"
        self.emails_file_path = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/assist_files/emails.txt"
        self.password_dump_path_prefix = r"/mnt/windows/Users/lordh/Documents/Svalbard/vault/dumps/password_dump-"
        self.first_names = self.get_list_from_file(self.first_names_file_path)
        self.last_names = self.get_list_from_file(self.last_names_file_path)
        self.adjectives = self.get_list_from_file(self.adjectives_file_path)
        self.common_nouns = self.get_list_from_file(self.common_nouns_file_path)
        self.emails = self.get_list_from_file(self.emails_file_path)

    def get_list_from_file(self, path):
        result = []
        with open(path, "r") as f:
            for line in f.readlines():
                result.append(line.strip())
        return result


class PasswordManager:
    def __init__(self, file_location):
        self.file_location = file_location
        self.data = self.decrypt_data()

    def encrypt_data(self, output_file_path):
        gpg = gnupg.GPG()
        encrypted_data = gpg.encrypt(
            json.dumps(self.data).encode("utf-8"),
            recipients=None,
            symmetric="AES256",
            passphrase=config.access_password,
            extra_args=["--s2k-mode", "3", "--s2k-count", "65011712", "--no-symkey-cache", "--digest-algo", "SHA256"],
            output=output_file_path,
        )

    def decrypt_data(self):
        gpg = gnupg.GPG()
        decrypted_data = gpg.decrypt_file(self.file_location, passphrase=config.access_password, extra_args=["--no-symkey-cache"])
        return json.loads(decrypted_data.data.decode("utf-8"))

    def print_colorized(self, entry, dictionary, index="", show_starred=True, show_starred_exception_keys=None):
        if show_starred_exception_keys is None:
            show_starred_exception_keys = []
        if not isinstance(index, str):
            console.print(f"{index} [yellow]{escape(entry)}[/yellow]")
        else:
            console.print(f"[yellow]{escape(entry)}[/yellow]")
        for key in dictionary:
            console.print(f"[blue]{escape(key)}[/blue]: ", end="")
            if show_starred and key not in show_starred_exception_keys:
                num_stars = len(dictionary[key])
                print("*" * num_stars)
            else:
                print(dictionary[key])

    def add_secure_password(self):
        # get length - ensure it is valid integer
        while True:
            try:
                length = int(input("Enter Length: "))
                break
            except ValueError:
                console.print("[red]Password length must be an integer[/red]")
        # ensure length is at least 8
        if length < 8:
            console.print("[red]Passwords of length smaller than 4 not allowed[/red]")
            return
        # define various character types
        lowercase_chars = string.ascii_lowercase
        uppercase_chars = string.ascii_uppercase
        digit_chars = string.digits
        special_chars = string.punctuation
        # add guaranteed characters (1 uppercase, 1 lowercase, 1 digit, 1 punctuation)
        guaranteed_chars = [secrets.choice(lowercase_chars), secrets.choice(uppercase_chars), secrets.choice(digit_chars), secrets.choice(special_chars)]
        # get available characters
        available_chars = lowercase_chars + uppercase_chars + digit_chars + special_chars
        # get remaining characters
        remaining_length = length - len(guaranteed_chars)
        remaining_chars = [secrets.choice(available_chars) for _ in range(remaining_length)]
        password_chars = guaranteed_chars + remaining_chars
        # cryptographically secure shuffle
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        return ''.join(password_chars)


    def choose_email(self):
        console.print()
        for ind, mail in enumerate(config.emails):
            console.print(f"{ind + 1}. {escape(mail)}")
        choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, len(config.emails) + 1))))
        return config.emails[choice - 1]

    def search(self, just_search=True):
        key = input("Enter term to search for: ")
        # creates an empty dictionary called search_results whose keys are the order in which the data returns entries and the values are the names of the entries
        search_results = {}
        for ind, entry in enumerate(self.data):
            if key.lower() in entry.lower():
                self.print_colorized(
                    entry, self.data[entry], ind, show_starred=True
                )  # during search the relevant part is just the name of the entry which is never starred
                search_results[ind] = entry
                print()
        if not just_search:
            # n_matches is the number of elements in the dictionary
            n_matches = len(search_results)
            # if there is no element in the dictionary then return an impossible value
            if n_matches == 0:
                return -1
            # if there is only one element in the dictionary then there is no sense in asking the user for a choice and we return the only possible value. dict.popitem() returns a tuple of (key, value) thus its first element is the value that we want
            if n_matches == 1:
                return search_results.popitem()[1]
            # if there is more than one element in the dictionary, then we ask the user to give us a valid value. list(dict) returns a list of the keys of the dictionary
            choice = IntPrompt.ask("Enter a number", choices=list(map(str, list(search_results))))
            return search_results[choice]

    def insert(self):
        entry = input("Enter term to insert: ")
        if entry in self.data:
            console.print(f"[red]Entry {escape(entry)} already exists in database.[/red]")
            return
        entry_dictionary = {}
        while True:
            console.print("\n")
            console.print("What do you want to do?")
            console.print("1. Add key: value pair")
            console.print("2. Auto Insert Password")
            console.print("3. Select Email from options")
            console.print("4. Add Random Username")
            console.print("5. Add Random First Name")
            console.print("6. Add Random Last Name")
            console.print("7. Add Random Space Separated First and Last Name")
            console.print("8. Add Random Non-Space Separated First and Last Name")
            console.print("9. Show full entry")  # added this
            console.print("10. Show specific key-value pair un-starred")
            console.print(
                "11. Submit entry"
            )  # no switch case for this since we directly update each time - with 10, we just exit the switch case
            choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, 12))))
            chosen_keys = None  # this is added to pass exception to the print_colorized function during display so that the key you have just entered does not show up starred
            if choice == 1:
                key = input("Enter key: ")
                if key in entry_dictionary:
                    console.print("[red]Key already exists. Update it.[/red]")
                    break
                entry_dictionary[key] = input("Enter value: ")
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 2:
                key = "Password"
                if key in entry_dictionary:
                    console.print(f"[red]{escape(key)} already exists. Update it.[/red]")
                    break
                else:
                    entry_dictionary[key] = self.add_secure_password()
                    pc.copy(entry_dictionary[key])
                    console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 3:
                key = "Email"
                entry_dictionary[key] = self.choose_email()
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 4:
                key = "Username"
                entry_dictionary[key] = random.choice(config.adjectives) + random.choice(config.common_nouns)
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 5:
                key = "First Name"
                entry_dictionary[key] = random.choice(config.first_names)
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 6:
                key = "Last Name"
                entry_dictionary[key] = random.choice(config.last_names)
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 7:
                key = "Separated Name"
                entry_dictionary[key] = random.choice(config.first_names) + " " + random.choice(config.last_names)
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 8:
                key = "Unseparated Name"
                entry_dictionary[key] = random.choice(config.first_names) + random.choice(config.last_names)
                pc.copy(entry_dictionary[key])
                console.print(f"[red]Value of key [/red][blue]{escape(key)}[/blue][red] copied to clipboard[/red]")
                chosen_keys = [key]
            elif choice == 9:
                chosen_keys = list(entry_dictionary.keys())
            elif choice == 10:
                key = input("Enter the key you want to see un-starred: ")
                if key not in entry_dictionary[entry]:
                    console.print(f"[red]{escape(key)} not among valid keys[/red]")
                else:
                    chosen_keys = [key]
            else:
                break
            console.print("The entry till now is (showing only the new key):")
            self.print_colorized(
                entry, entry_dictionary, show_starred=True, show_starred_exception_keys=chosen_keys
            )  # during insert we only care about the current key that we have inserted
        console.print("Entry added is (starred - use the option to show all entries to see everything):")
        self.print_colorized(
            entry, entry_dictionary, show_starred=True
        )  # after the full entry, we might want to see it all together - but we should use the specific option for it
        self.data[entry] = entry_dictionary

    def delete(self):
        entry = self.search(just_search=False)
        if entry == -1:
            console.print("[red]There is no such entry and so it cannot be deleted[/red]")
            return
        console.print("The chosen entry is:")
        self.print_colorized(
            entry, self.data[entry], show_starred=False
        )  # during deletion, we might want to see the full entry (maybe? maybe not?)
        console.print("[yellow]Are you sure you want to delete?[/yellow]")
        console.print("1. [green]Yes[/green]")
        console.print("2. [red]No[/red]")
        choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, 3))))
        if choice == 1:
            del self.data[entry]
            console.print(f"[red]Entry {escape(entry)} deleted[/red]")
        else:
            console.print(f"{escape(entry)} has not been deleted")

    def update(self):
        entry = self.search(just_search=False)
        if entry == -1:
            console.print("[red]There is no such entry and so it cannot be updated[/red]")
            return
        console.print(f"You have chosen to update {escape(entry)}")
        self.print_colorized(
            entry, self.data[entry], show_starred=True
        )  # during update, we definitely want to see the full entry - but we should use the specific option meant for that
        while True:
            print()
            console.print("What do you want to do?")
            console.print("1. Update the value of an existing entry")
            console.print("2. Update the key of an existing entry")
            console.print("3. Delete a key: value pair")
            console.print("4. Add a key: value pair")
            console.print("5. Auto Update the Password key (generate it if it does not exist)")
            console.print("6. Choose a different Email from options")
            console.print("7. Update name of entry")
            console.print("8. Show all entries")  # added this
            console.print("9. Show a specific key-value pair un-starred")
            console.print("10. [red]Exit Update Interface[/red]")
            choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, 11))))
            chosen_keys = None  # this is being used to ensure that for the key whose value is changed or for the new key that is added, its value is not being shown as just stars
            if choice == 1:
                key = input("Enter key whose value you want to update: ")
                if key not in self.data[entry]:
                    console.print(f"[red]{escape(key)} not valid[/red]")
                    return
                value = input(f"Enter value of {escape(key)}: ")
                self.data[entry][key] = value
                chosen_keys = [key]
            elif choice == 2:
                key = input("Enter key to update: ")
                if key not in self.data[entry]:
                    console.print(f"[red]{escape(key)} not valid[/red]")
                    return
                value = self.data[entry][key]
                del self.data[entry][key]
                key = input("Enter new key: ")
                self.data[entry][key] = value
                chosen_keys = [key]
            elif choice == 3:
                key = input("Enter key to delete: ")
                if key not in self.data[entry]:
                    console.print(f"[red]{escape(key)} not valid[/red]")
                    return
                del self.data[entry][key]
            elif choice == 4:
                key = input("Enter the new key: ")
                if key in self.data[entry]:
                    console.print(f"[red]{escape(key)} already exists[/red]")
                    return
                value = input(f"Enter the value of {escape(key)}: ")
                self.data[entry][key] = value
                chosen_keys = [key]
            elif choice == 5:
                self.data[entry]["Password"] = self.add_secure_password()
                chosen_keys = ["Password"]
            elif choice == 6:
                self.data[entry]["Email"] = self.choose_email()
                chosen_keys = ["Email"]
            elif choice == 7:
                temp_dictionary = self.data[entry]
                del self.data[entry]
                entry = input("Enter new name for entry: ")
                self.data[entry] = temp_dictionary
            elif choice == 8:
                chosen_keys = list(self.data[entry].keys())
            elif choice == 9:
                key = input("Enter the key you want to see un-starred: ")
                if key not in self.data[entry]:
                    console.print(f"[red]{escape(key)} not among valid keys[/red]")
                else:
                    chosen_keys = [key]
            elif choice == 10:
                console.print("The updated entry is (starred - use show all entries option to see everything):")
                self.print_colorized(
                    entry, self.data[entry], show_starred=True
                )  # after we have made our changes, we also definitely want to see the full entry - but we should use the option to show all data instead of seeing here
                break
            console.print("The updated entry is:")
            self.print_colorized(
                entry, self.data[entry], show_starred=True, show_starred_exception_keys=chosen_keys
            )  # while updating we only care about the entry we have changed or updated or added

    def copy(self):
        entry = self.search(just_search=False)
        if entry == -1:
            console.print("[red]There is no such entry and so it cannot be copied[/red]")
            return
        console.print(f"You have chosen to copy from {escape(entry)}")
        self.print_colorized(entry, self.data[entry], show_starred=True)  # during copy we shouldn't care about seeing the actual entry
        while True:
            print()
            console.print("What do you want to copy?")
            copy_list = [entry]
            console.print(f"1. Name of [blue]entry[/blue]: [green]{escape(entry)}[/green]")
            for ind, key in enumerate(self.data[entry]):
                copy_list.append(self.data[entry][key])
                console.print(f"{ind+2}. The value of [blue]{escape(key)}[/blue]: ", end="")
                print(
                    "*" * len(self.data[entry][key])
                )  # I have modified this so that it directly only gets copied, instead of being displayed
            console.print(f"{len(copy_list) + 1}. [red]Exit Copy Interface[/red]")
            choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, len(copy_list) + 2))))
            if choice == len(copy_list) + 1:
                break
            pc.copy(copy_list[choice - 1])

    def dump(self):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S-%Z")
        dump_path = config.password_dump_path_prefix + timestamp + ".enc"
        self.encrypt_data(dump_path)
        console.print(f"[green]Passwords dumped to file: {dump_path}[/green]")


def main():
    file_location = config.pwd_file_path
    try:
        password_manager = PasswordManager(file_location)
    except Exception as e:
        console.print("[red]Access Password entered is incorrect. Exiting Program[/red]")
        return
    while True:
        console.print("\n\n", "-" * 30)
        console.print("What do you want to do?")
        console.print("1. Search")
        console.print("2. Insert")
        console.print("3. Delete")
        console.print("4. Update")
        console.print("5. Copy")
        console.print("6. Dump")
        console.print("7. Exit")
        choice = IntPrompt.ask("Enter a number", choices=list(map(str, range(1, 8))))
        if choice == 1:
            password_manager.search()
        elif choice == 2:
            password_manager.insert()
        elif choice == 3:
            password_manager.delete()
        elif choice == 4:
            password_manager.update()
        elif choice == 5:
            password_manager.copy()
        elif choice == 6:
            password_manager.dump()
        else:
            break
        password_manager.encrypt_data(file_location)


if __name__ == "__main__":
    config = Config()
    main()
