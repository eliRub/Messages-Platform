import os
from dotenv import load_dotenv
import mysql.connector as sql
from datetime import datetime
from colorama import Fore
import bcrypt
import inspect
import smtplib
import ssl
from email.message import EmailMessage
import re
import random


load_dotenv()  # This function is loading the ENVIRONMENT-VARIABLES from the .env file.
""" Here I connect to the MySQL server at the first time, before I created the DB. """
# mydb = sql.connect(
#     user=os.getenv("DB_USERNAME"),
#     password=os.getenv("DB_PASSWORD"),
#     host=os.getenv("DB_HOST"),
# )

""" Here I create a database called 'messages_platform', connect to it, and create table called users_table."""
# my_cursor = MY_DB.cursor()
# my_cursor.execute("CREATE DATABASE messages_platform")
# my_db.commit()
# MY_DB = sql.connect(
#     user=os.getenv("DB_USERNAME"),
#     password=os.getenv("DB_PASSWORD"),
#     host=os.getenv("DB_HOST"),
#     database="messages_platform"
# )
# MY_CURSOR = MY_DB.cursor()


def create_user(u_mail: str, username: str, password: str):
    """ This function create a new user in the system, and inserts his details to the 'Users' table in the DB.
    """
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        # Checking if email address is valid.
        valid_email = is_email_address_valid(u_email=u_mail)
        if not valid_email:
            return

        # Checking if the email owner already has an account with this email address.
        MY_CURSOR.execute("SELECT user_mail FROM Users")
        cursor_result = MY_CURSOR.fetchall()
        if (u_mail,) in cursor_result:
            print(Fore.RED + "This email address has been registered already." + Fore.RESET)
            return

        # Checking if the email the user entered belong to him/her.
        generate_code_validation = random.randint(10000, 1000000)
        send_email_validation(u_mail=u_mail, validation_code=generate_code_validation)

        # Encrypt password.
        password = password.encode('utf-8')  # Convert the password to bytes
        salt = bcrypt.gensalt()  # Generate a random salt
        hashed_password = bcrypt.hashpw(password, salt)  # Hash the password with the salt

        try:
            user_code_entered = int(input("Type the validation_code you receive in your email:  "))
            if generate_code_validation == user_code_entered:
                # Here I pick the new user_id for the new user.
                MY_CURSOR.execute("SELECT user_id FROM Users ORDER BY user_id DESC LIMIT 1")
                cursor_result = MY_CURSOR.fetchall()
                user_id = cursor_result[0][0] + 1

                # Like in this case I did in all the code - I used parameterized queries to prevent SQL injection attacks.
                sql_quote = "INSERT INTO Users (user_id, user_mail, username, salt, hashed_password) VALUES (%s, %s, %s, %s, %s)"
                val = (user_id, u_mail, username, salt, hashed_password)
                MY_CURSOR.execute(sql_quote, val)
                print("You have registered successfully!")
                MY_DB.commit()
                return True, u_mail
            else:
                print(Fore.RED + "The verification code is incorrect!\n" + Fore.RESET)
        except ValueError as err:
            print(Fore.RED + f"You can't enter nothing but DIGITS!\nERROR: {err}" + Fore.RESET)


def is_email_address_valid(u_email: str):
    regex = r'^[a-zA-Z0-9\.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$'
    if re.fullmatch(regex, u_email):
        return True
    else:
        print(Fore.RED + "Invalid Email." + Fore.RESET)
        return False


def send_email_validation(u_mail: str, validation_code: int):
    """ """
    smtp_servers = {
        "gmail.com": ("smtp.gmail.com", 465),
        "yahoo.com": ("smtp.mail.yahoo.com", 465),
        "outlook.com": ("smtp-mail.outlook.com", 587),
    }

    smtp_server, port = smtp_servers["gmail.com"]  # While I'm using my gmail account for sending the mails.
    sender_email = os.getenv("SENDER_EMAIL")
    receiver_email = u_mail
    sender_password = os.getenv("SENDER_EMAIL_PASSWORD")
    message = EmailMessage()
    SUBJECT = "Checking email validation."
    message["Subject"] = SUBJECT
    message["From"] = sender_email
    message["To"] = receiver_email
    message.set_content(f"Hi there, \nthis is your code: {validation_code}")

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(host=smtp_server, port=port, context=context) as server:
            server.login(user=sender_email, password=sender_password)
            server.send_message(message)
    except Exception as e:
        print(f"SMTP Connection Error:  {e}")


def login(email: str, password: str):
    """ This function takes an email and password from the user and if the email exist and the password is correct,
        it will log into the platform.
    """
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        provided_password = password.encode()  # Convert the provided password to bytes

        # Retrieve the `salt` and `hashed_password` from the database associated with the user's account
        sql_quote = "SELECT salt, hashed_password FROM Users WHERE user_mail = %s"
        val = (email,)
        MY_CURSOR.execute(sql_quote, val)
        cursor_result = MY_CURSOR.fetchall()

        # Checking if the email is exists.
        calling_frame = inspect.currentframe().f_back
        line_number = calling_frame.f_lineno
        if not cursor_result:
            # The username doesn't exist.
            print(Fore.RED + "This email has not been registered yet." + Fore.RESET + f"\t Line: {line_number}")
            return False
        # print(cursor_result, type(cursor_result))
        salt, stored_hashed_password = cursor_result[0][0].encode(), cursor_result[0][1]

        # Hash the provided password with the retrieved `salt`, the salt have to be encodes before it hashed - it string.
        hashed_provided_password = bcrypt.hashpw(provided_password, salt).decode()

        # Compare the `hashed_provided_password` with the stored `hashed_password`
        if hashed_provided_password == stored_hashed_password:
            # Password is correct, authenticate the user
            print("Login success.")
            return True
        else:
            # Password is incorrect, reject the login
            # Compare the `hashed_provided_password` with the stored `hashed_password`
            print(Fore.RED + "The password is incorrect!" + Fore.RESET + f"\t Line: {line_number}")
            return False


def reset_password(u_email: str):
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        # Checking if the email entered by the user is valid.
        flag = is_email_address_valid(u_email=u_email)
        if not flag:
            return

        # Checking if the email the user entered belong to him/her.
        generate_validation_code = random.randint(10000, 1000000)
        send_email_validation(u_mail=u_email, validation_code=generate_validation_code)

        try:
            user_code_entered = int(input("Type the verification code you receive in your email:  "))
            if user_code_entered == generate_validation_code:
                new_password = input("Entered your new password:  ")

                # Encrypt password.
                password = new_password.encode('utf-8')  # Convert the password to bytes
                salt = bcrypt.gensalt()  # Generate a random salt
                hashed_password = bcrypt.hashpw(password, salt)  # Hash the password with the salt

                sql_quote = "UPDATE Users SET salt = %s, hashed_password = %s WHERE user_mail = %s "
                values = (salt, hashed_password, u_email)
                MY_CURSOR.execute(sql_quote, values)
                MY_DB.commit()
                print("Password changed!")
            else:
                print(Fore.RED + "The verification code is incorrect!\n" + Fore.RESET)
        except ValueError as err:
            print(Fore.RED + f"You can't enter nothing but DIGITS!\nERROR: {err}" + Fore.RESET)


def create_chat(user1_mail: str, user2_mail: str):
    """ This function take 2 usernames, open new chat for them with unique chat_id,
        and add this chat to Chats table.
    """
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        sql_quote = "SELECT user_id FROM Users WHERE user_mail = %s"
        val = (user1_mail,)
        MY_CURSOR.execute(sql_quote, val)
        user1_id = MY_CURSOR.fetchall()[0][0]

        sql_quote = "SELECT user_id FROM Users WHERE user_mail = %s"
        val = (user2_mail,)
        MY_CURSOR.execute(sql_quote, val)
        cursor_result = MY_CURSOR.fetchall()
        if not cursor_result:
            print("This Email is not registered.")
            return
        user2_id = cursor_result[0][0]

        # I order them so if I will get any 2 users_id I will know what they chat_id,
        # cause it - their names sorted with '0' in the middle.
        users_list = [user1_id, user2_id]
        users_list.sort()
        chat_id = int(f"{users_list[0]}0{users_list[1]}")

        # Checking if the conversation already exists.
        try:
            # Adding the chat to the 'Chats' table.
            sql_quote = "INSERT INTO Chats (chat_id, user1_id, user2_id) VALUES (%s, %s, %s)"
            val = (chat_id, user1_id, user2_id)
            MY_CURSOR.execute(sql_quote, val)
            MY_DB.commit()
            print("Conversation created successfully.")
        except sql.errors.IntegrityError as err:
            calling_frame = inspect.currentframe().f_back
            line_number = calling_frame.f_lineno
            if err.errno == 1062:
                print(Fore.RED + "This conversation already exists!" + Fore.RESET + f"\t Line: {line_number}")
            elif err.errno == 1452:
                print(Fore.RED + "This user doesn't exist!" + Fore.RESET + f"\t Line: {line_number}")
            else:
                print(Fore.RED + f"An error occurred: {err}" + Fore.RESET + f"\t Line: {line_number}")


def add_message_to_db(sender_mail: str, receiver_mail: str, message_content: str):
    """ This function takes the name of the user who send the message and the user who will receive it,
        and the message itself, and add the message to the 'Messages' table with all the metadata.
    """
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        # Here I check if the emails are valid and exists in the system.
        emails = [sender_mail, receiver_mail]
        id_list = []
        for email in emails:
            sql_quote = "SELECT user_id FROM Users WHERE user_mail = %s"
            val = (email,)
            MY_CURSOR.execute(sql_quote, val)
            cursor_result = MY_CURSOR.fetchall()
            if not cursor_result:
                print(Fore.RED + "Invalid or missing Email." + Fore.RESET)
                return
            id_list.append(cursor_result[0][0])

        sender_id, receiver_id = id_list[0], id_list[1]

        # Here I get the chat_id.
        users_list = [sender_id, receiver_id]
        users_list.sort()
        chat_id = int(f"{users_list[0]}0{users_list[1]}")

        # Here I choose which message_id will be for the message.
        MY_CURSOR.execute("SELECT message_id FROM Messages ORDER BY message_id DESC LIMIT 1")
        cursor_result = MY_CURSOR.fetchall()
        message_id = cursor_result[0][0] + 1

        # Format date and time values
        date = datetime.now().strftime("%Y-%m-%d")
        time = datetime.now().strftime("%H:%M:%S")
        # Checking if the conversation btw the 2 users exists.
        try:
            # Use STR_TO_DATE() for date and TIME() for time
            sql_quote = """ INSERT INTO Messages (message_id, chat_id, message_content, date, time, sender_id, receiver_id)
                            VALUES (%s, %s, %s, STR_TO_DATE(%s, '%Y-%m-%d'), TIME(%s), %s, %s) """
            val = (message_id, chat_id, message_content, date, time, sender_id, receiver_id)

            MY_CURSOR.execute(sql_quote, val)
            MY_DB.commit()

        except sql.errors.IntegrityError as err:
            calling_frame = inspect.currentframe().f_back
            line_number = calling_frame.f_lineno
            if err.errno == 1452:
                print(Fore.RED + f"You have not yet opened a chat with this user."
                      + Fore.RESET + f"\t Line: {line_number}")
            else:
                print(Fore.RED + f"An error occurred: {err}" + Fore.RESET + f"\t Line: {line_number}")


def show_chat(user1_mail: str, user2_mail: str):
    """ This function takes 2 users and show the all conversations between them, ever."""
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        # Here I check if the emails are valid and exists in the system.
        emails = [user1_mail, user2_mail]
        id_list = []
        for email in emails:
            sql_quote = "SELECT user_id FROM Users WHERE user_mail = %s"
            val = (email,)
            MY_CURSOR.execute(sql_quote, val)
            cursor_result = MY_CURSOR.fetchall()
            if not cursor_result:
                print(Fore.RED + "Invalid or missing Email." + Fore.RESET)
                return
            id_list.append(cursor_result[0][0])

        user1_id, user2_id = id_list[0], id_list[1]
        users_list = [user1_id, user2_id]
        users_list.sort()
        chat_id = int(f"{users_list[0]}0{users_list[1]}")

        # Checking if 'chat_id' exists.
        MY_CURSOR.execute("SELECT chat_id FROM Chats")
        cursor_result = MY_CURSOR.fetchall()
        if (chat_id,) not in cursor_result:
            print(Fore.LIGHTYELLOW_EX + "You need to open a chat first." + Fore.RESET)
            return

        sql_quote = f""" SELECT U1.username, M.message_content, M.date, M.time
                         FROM Messages as M 
                         INNER JOIN Users AS U1 ON M.sender_id = U1.user_id
                         INNER JOIN Users As U2 ON M.receiver_id = U2.user_id
                         WHERE (M.sender_id = %s AND M.receiver_id = %s) OR (M.sender_id = %s AND M.receiver_id = %s)
                         ORDER BY M.date, M.time  
                    """
        val = (user1_id, user2_id, user2_id, user1_id)

        MY_CURSOR.execute(sql_quote, val)
        all_messages = MY_CURSOR.fetchall()

        if not all_messages:
            print(Fore.RED + "There is nothing to show." + Fore.RESET)
            return

        for sender, message, date, time in all_messages:
            print(Fore.MAGENTA + f"{sender}: " + Fore.LIGHTYELLOW_EX + message + f"\t[D:{date}, T:{time}]" + Fore.RESET)


def reveal_all_user_chas(user_mail: str):
    with sql.connect(
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            database="messages_platform"
    ) as MY_DB:
        MY_CURSOR = MY_DB.cursor()

        pre_sql_quote = "SELECT user_id, username FROM Users WHERE user_mail = %s"
        val = (user_mail,)
        MY_CURSOR.execute(pre_sql_quote, val)
        cursor_result = MY_CURSOR.fetchall()
        user_id = cursor_result[0][0]
        username = cursor_result[0][1]

        sql_quote = """ SELECT u.user_id, u.username, u.user_mail
                        FROM Chats AS c
                        JOIN Users AS u
                        ON (c.user1_id = u.user_id) OR (c.user2_id = u.user_id)
                        WHERE c.user1_id = %s OR c.user2_id = %s
                        """
        val = (user_id, user_id)

        MY_CURSOR.execute(sql_quote, val)
        people_you_have_chats_with = MY_CURSOR.fetchall()

        # Removing the data on the user_id itself because there are duplicates data, and adding to dict all the other users.
        chats_dict = {user_mail: username for id, username, user_mail in people_you_have_chats_with if id != user_id}
        if (user_id, "Jeff", user_mail) in people_you_have_chats_with:
            chats_dict[user_mail] = username

        print("Your Chats:  ", chats_dict)


def main():
    """ Here I tested the above functions. """

    # MY_CURSOR.execute(""" CREATE TABLE Users (user_id INT AUTO_INCREMENT PRIMARY KEY,
    #                                           user_mail VARCHAR(40),
    #                                           username VARCHAR(255) NOT NULL,
    #                                           salt VARCHAR(50),
    #                                           hashed_password CHAR(70) NOT NULL) """)
    # MY_DB.commit()
    # Because that the user_id is the primary key, the default order in this table will be order-by user_id.

    # MY_CURSOR.execute(""" CREATE TABLE Chats (chat_id INT AUTO_INCREMENT PRIMARY KEY,
    #                                           user1_id INT,
    #                                           user2_id INT,
    #                                           FOREIGN KEY (user1_id) REFERENCES Users(user_id),
    #                                           FOREIGN KEY (user2_id) REFERENCES Users(user_id)) """)
    # MY_DB.commit()

    # MY_CURSOR.execute(""" CREATE TABLE Messages (message_id INT AUTO_INCREMENT PRIMARY KEY,
    #                                              chat_id INT,
    #                                              message_content VARCHAR(1000),
    #                                              date DATE,
    #                                              time TIME,
    #                                              sender_id INT,
    #                                              receiver_id INT,
    #                                              FOREIGN KEY (chat_id) REFERENCES Chats(chat_id),
    #                                              FOREIGN KEY (sender_id) REFERENCES Users(user_id),
    #                                              FOREIGN KEY (receiver_id) REFERENCES Users(user_id)) """)
    # MY_DB.commit()

    # TABLES:
    # MY_CURSOR.execute("SHOW TABLES")
    # result = MY_CURSOR.fetchall()
    # print(Fore.LIGHTMAGENTA_EX + "TABLES: " + Fore.RESET)
    # for x in result:
    #     print(x)

    # create_user(u_mail="elirub2003@gmail.com", username="Jeff", password="12345")
    # login(email="elirub2003@gmail.com", password="12345")

    # USERS:
    # MY_CURSOR.execute("SELECT * FROM users")
    # result = MY_CURSOR.fetchall()
    # print(Fore.LIGHTMAGENTA_EX + "USERS: " + Fore.RESET)
    # for x in result:
    #     print(x)

    # create_chat(user1_mail="elirub2003@gmail.com", user2_mail="chani.rub@gmail.com")

    # CHATS:
    # MY_CURSOR.execute("SELECT * FROM Chats")
    # result = MY_CURSOR.fetchall()
    # print(Fore.LIGHTMAGENTA_EX + "CHATS: " + Fore.RESET)
    # for x in result:
    #     print(x)

    # add_message_to_db(sender_mail="elirub2002@gmail.com",
    #                   receiver_mail="forapractice@yahoo.com",
    #                   message_content="Are you free tomorrow ? ")

    # MESSAGES:
    # MY_CURSOR.execute("SELECT * FROM Messages")
    # result = MY_CURSOR.fetchall()
    # print(Fore.LIGHTMAGENTA_EX + "MESSAGES: " + Fore.RESET)
    # for x in result:
    #     print(x)

    # show_chat("elirub2003@gmail.com", "forapractice@yahoo.com")

    # reveal_all_user_chas("elirub2002@gmail.com")

    """ End of the test. """
    ####################################################################################################################

    u_mail = ""
    while True:
        user_answer = (
            input("\nHi, These are your options: login, signup, reset-passwrd, exit\n(type 'login' for login, "
                  "'sign' for signup, 'reset' for reset and 'exit' for exit - at any time):\n")).lower()

        valid = False
        if user_answer.strip() == "login":
            u_mail = input("Enter your email:  ")
            password = input("Enter your password:  ")
            valid = login(email=u_mail.strip(), password=password.strip())
        elif user_answer == "sign":
            u_mail = input("Enter your email:  ")
            username = input("Choose username:  ")
            password = input("Choose password:  ")
            valid = create_user(u_mail=u_mail.strip(), username=username.strip(), password=password.strip())
            if valid:
                print(f"This is your details: (email: {valid[1]}, username: {username}, password: {password})")
        elif user_answer.strip() == "reset":
            u_mail = input("Type your email address: ")
            reset_password(u_email=u_mail.strip())
        elif user_answer == "exit":
            print("Bye :)")
            return
        else:
            print("Enter only valid value.")

        if valid:
            break

    print("You are in the system now! ")
    print("Now you can open a new chat with some user, or see some of your chats or send a message to someone.")
    while True:

        user_answer = (input("For open a new chat with a user, type: 'new chat', For see your own chats, "
                             "type: 'my chats', For send message to your friend type 'send'.\n")).lower()

        if user_answer.strip() == "new chat":
            other_mail = input("Enter other user-mail:  ")
            create_chat(user1_mail=u_mail.strip(), user2_mail=other_mail.strip())
        elif user_answer.strip() == "my chats":
            reveal_all_user_chas(u_mail.strip())
            other_user_mail = input("Do you want to see one of your chats with these users? "
                                    "if yes, than enter his email:\n")
            if other_user_mail.lower() == "exit":
                return
            show_chat(u_mail.strip(), other_user_mail.strip())
        elif user_answer.strip() == "send":
            other_mail = input("Enter other user-mail:  ")
            message = input("Enter Message:  ")
            add_message_to_db(sender_mail=u_mail.strip(), receiver_mail=other_mail.strip(), message_content=message.strip())
        elif user_answer.strip() == "exit":
            return
        else:
            print("Type only valid value.")


if __name__ == '__main__':
    main()
