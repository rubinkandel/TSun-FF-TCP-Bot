<div align="center">

# ✨ TSunTCP Bot ✨

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/Dependencies-Installed-brightgreen?style=for-the-badge)](./requirements.txt)
[![Status: Active](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)](https://github.com/your-username/GIVEAWAYTCP/commits/main)

</div>

---

<div align="center">

## 🚀 Overview

Welcome to the **TSunTCP Bot**! This powerful bot is designed to interact with the Free Fire game's TCP protocol, offering a wide array of functionalities.

</div>

---
<div align="center">

## 🌟 Features
</div>

*   **Advanced Squad Management:** Create, join, invite, and manage in-game squads with ease.
*   **Comprehensive Player Info:** Retrieve detailed information and status updates for any player ID.
*   **Interaction & Spamming:** Send friend requests, invites, and join requests to players.
*   **"Attack" & Lag Capabilities:** Tools to influence in-game team performance (use responsibly).
*   **Automated Restart:** Self-recovers from connection issues and errors, ensuring high uptime.
*   **Secure Communication:** Utilizes AES encryption for packet handling.
*   **Detailed Logging:** Keeps track of all bot activities and errors for easy debugging.

---

## 🛠️ Installation

## On Vercel
1. Clone This Repo.
2. Create Account On Vercel.
3. Deploy This Repo On Vercel And Enjoy.

## On Local Host

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/saeedx302/TSun-TCP-Bot.git
    cd GIVEAWAYTCP
    ```

2.  **Install Dependencies:**
    Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration (`bot.txt`):**
    Create a `bot.txt` file in the project root directory. This file should contain your bot's login credentials in JSON format.
    ```json
    {
        "12345678": "11F28FE8BD89468DBB39EF44E7CEF538EA...."
    }
    ```
    *Replace with your actual bot credentials `UID` and `PASSWORD` .*
    ```json
    Change Region To Your Own Region On Lines : 
    799, 862, 884, 1077, 1090

    Change Uid With Your Own Guest Uid On Lines : 
    841, 960, 988, 1030, 1052, 1072
    ```

4.  **Start:**
    For Start Bot Run This Command In Terminal.
    ```json
    python app.py
    ```
---
<div align="center">

## 🎮 In-Game Commands
</div>

The TSunTCP Bot Support These Commands In Game. Some Commands In Beta. So Some Commands Show Error Sometime. `(We Are Working On It)`

### 👥 Group & Squad Management

| Command                 | Description                                                               |
| :---------------------- | :------------------------------------------------------------------------ |
| `/3`                   | Creates a 3-player group.                                               |
| `/4`                   | Creates a 4-player group.                                                  |
| `/5`                   | Creates a 5-player group.                                                  |
| `/6`                   | Creates a 6-player group.                                                  |
| `/inv [uid]`     | Invites a specific player to your current squad.                          |
| `/join [team_code]`    | Joins a squad using a specific team code. |
| `/solo`                | Leaves if In group/squad and Return To solo mode.                  |
| `/addVOPN [uid] [Squad Type]` | Creates a squad and invites the specified player  `(In Beta)`. |

### 📩 Spam & Interaction

| Command                 | Description                                                               |
| :---------------------- | :------------------------------------------------------------------------ |
| `/spam [player_id]`    | Spams friend requests to the specified player.                            |
| `/x [player_id]`       | Spams invite requests to the specified player.                            |
| `/sm [player_id]`      | Spams join requests to the specified player.                              |
| `@a [target_id] [emote_id]` | Sends a specific emote to one or more target players.                     |
| `@b [target_id] [emote_id]` | Spams a specific emote to one or more target players.                     |

### 💥 Attack & Lag (Use Responsibly)

| Command                 | Description                                                               |
| :---------------------- | :------------------------------------------------------------------------ |
| `/lag [team_id]`       | Attempts to cause lag for the specified team.                             |
| `/lag [team_id] 2`     | Attempts to cause lag for the specified team using an alternative method. |
| `/attack [team_id]`    | Initiates an "attack" on the specified team.                              |
| `/start [team_id]`     | Attempts to force-start a game for the specified team.                    |
| `/room [player_id]`    | Spams a player if they are currently in a room.                           |

### ℹ️ General Information

| Command                 | Description                                                               |
| :---------------------- | :------------------------------------------------------------------------ |
| `/likes [player_id]`   | Grants 100 likes to the specified player's profile. `(In Beta)`                          |
| `/info [player_id]`    | displays full information about the specified player.       |
| `/status [player_id]`  | displays the current in-game status of the specified player.   |
| `/visit [player_id]`   | Increases the visitor count on the specified player's profile.            |
| `/check [player_id]`   | Checks the ban status of the specified player.                            |
| `/region`              | Displays information about available game regions.                        |

### 🧠 Extra & AI

| Command                 | Description                                                               |
| :---------------------- | :------------------------------------------------------------------------ |
| `/biccco [player_id]`  | Retrieves and displays the specified player's in-game bio.`(In Beta)`                |
| `/ai [word]`           | Asks Bharat AI a question or provides a prompt.                           |
| `/admin`               | Displays information about the bot's administrator.                       |

---

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to open an issue or submit a pull request.

---

## 📄 License

This project is open-source and available under the MIT License.

---
