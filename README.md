# Poker Night Tracker

A web application to track poker game sessions and manage player balances.

## Features

- Password-protected access
- Add and manage players
- Record game sessions with:
  - Buy-in amounts
  - Final chip counts
  - Chip values
- Track current balances
- Generate monthly summaries
- Calculate debt settlements

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

5. Login with the default credentials:
   - Username: admin
   - Password: admin123

**Note**: Please change the default password after first login for security purposes.

## Usage

1. **Adding Players**:
   - Click on the "Add New Player" form
   - Enter the player's name
   - Click "Add Player"

2. **Recording Game Sessions**:
   - Select a player from the dropdown
   - Enter the buy-in amount in NIS
   - Enter the final chip count
   - Enter the chip value in NIS
   - Click "Add Game Session"

3. **Viewing Balances**:
   - Current balances are shown in the players table
   - Click "View Monthly Summary" to see detailed monthly balances and debt settlements

4. **Monthly Summary**:
   - Shows current balances for all players
   - Displays who owes whom and how much
   - Color-coded status indicators (green for winning, red for losing)

## Security Note

The default admin password should be changed in production. To do this, you can modify the `app.py` file and update the password in the `if __name__ == '__main__':` block. 