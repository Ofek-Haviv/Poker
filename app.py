from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# Use PostgreSQL in production and SQLite in development
if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///poker.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create tables at startup
with app.app_context():
    db.create_all()

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # Allow null for users without groups
    is_super_admin = db.Column(db.Boolean, default=False)  # Main admin that controls everything
    is_group_owner = db.Column(db.Boolean, default=False)  # Created the group, can't be removed
    is_group_admin = db.Column(db.Boolean, default=False)  # Can manage group members and games
    is_approved = db.Column(db.Boolean, default=True)  # Default to True since group approval happens separately
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    player = db.relationship('Player', backref='user', uselist=False)
    
    @property
    def groups(self):
        # For now, return a list containing just the user's group
        # In the future, this could be expanded to support multiple groups
        return [self.group] if self.group else []

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    join_code = db.Column(db.String(20), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    users = db.relationship('User', backref='group', lazy=True, foreign_keys=[User.group_id])
    owner = db.relationship('User', foreign_keys=[owner_id])
    players = db.relationship('Player', backref='group', lazy=True)
    game_sessions = db.relationship('GameSession', backref='group', lazy=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_participations = db.relationship('GameParticipation', backref='player', lazy=True)

class GameSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_chips = db.Column(db.Float, nullable=False)
    chips_value = db.Column(db.Float, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    participations = db.relationship('GameParticipation', backref='game', lazy=True)
    is_archived = db.Column(db.Boolean, default=False)

class GameParticipation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game_session.id'), nullable=False)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=False)
    buy_in = db.Column(db.Float, nullable=False)
    final_amount = db.Column(db.Float, nullable=False)

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    date_requested = db.Column(db.DateTime, default=datetime.utcnow)
    date_processed = db.Column(db.DateTime)

    user = db.relationship('User', backref='group_memberships')
    group = db.relationship('Group', backref='memberships')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if not current_user.group_id:
        # User hasn't joined a group yet
        return render_template('choose_group.html')
    
    # Only show players from the current user's group that were created by the current user
    players = Player.query.filter_by(
        group_id=current_user.group_id,
        user_id=current_user.id
    ).all()
    
    return render_template('index.html', players=players, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_approved:
                flash('Your account is pending approval from an admin.')
                return redirect(url_for('login'))
            
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_player', methods=['POST'])
@login_required
def add_player():
    name = request.form.get('name')
    if name:
        player = Player(
            name=name,
            group_id=current_user.group_id,
            user_id=current_user.id
        )
        db.session.add(player)
        db.session.commit()
        flash('Player added successfully')
    return redirect(url_for('index'))

@app.route('/add_game', methods=['POST'])
@login_required
def add_game():
    try:
        # Get form data
        player_ids = request.form.getlist('player_id[]')
        buy_ins_chips = [float(amount) for amount in request.form.getlist('buy_in[]')]  # Now in chips
        final_amounts = [float(amount) for amount in request.form.getlist('final_amount[]')]
        chips_value = float(request.form.get('chips_value'))
        
        # Calculate total chips
        total_final_chips = sum(final_amounts)
        total_buy_in_chips = sum(buy_ins_chips)
        
        # Debug information
        print(f"Player IDs: {player_ids}")
        print(f"Buy-ins (in chips): {buy_ins_chips}")
        print(f"Final amounts (in chips): {final_amounts}")
        print(f"Total final chips: {total_final_chips}")
        print(f"Total buy-in chips: {total_buy_in_chips}")
        print(f"Difference: {abs(total_final_chips - total_buy_in_chips)}")
        
        # Verify total chips match buy-ins (now both in chips)
        if abs(total_final_chips - total_buy_in_chips) > 0.01:  # Allow small floating point differences
            flash(f'Error: Total chips on table ({total_final_chips}) do not match total buy-ins ({total_buy_in_chips})! Difference: {abs(total_final_chips - total_buy_in_chips)}')
            return redirect(url_for('index'))
        
        # Create game session with group_id and created_by
        game = GameSession(
            total_chips=total_final_chips,
            chips_value=chips_value,
            group_id=current_user.group_id,  # Add group_id
            created_by=current_user.id  # Add created_by
        )
        db.session.add(game)
        db.session.commit()
        
        # Add participations (convert chips to NIS when storing)
        for player_id, buy_in_chips, final_amount in zip(player_ids, buy_ins_chips, final_amounts):
            participation = GameParticipation(
                game_id=game.id,
                player_id=player_id,
                buy_in=float(buy_in_chips),  # Store in chips
                final_amount=float(final_amount)  # Store in chips
            )
            db.session.add(participation)
        
        db.session.commit()
        flash('Game session added successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding game session: {str(e)}')
    
    return redirect(url_for('index'))

@app.route('/monthly_summary')
@login_required
def monthly_summary():
    # Get all games from the current month that are not archived
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    
    games = GameSession.query.filter(
        db.extract('month', GameSession.date) == current_month,
        db.extract('year', GameSession.date) == current_year,
        GameSession.is_archived == False
    ).all()
    
    # Calculate balances
    balances = {}
    for game in games:
        for participation in game.participations:
            player = participation.player
            if player.name not in balances:
                balances[player.name] = 0
            # Calculate profit/loss in NIS
            # Convert both final amount and buy-in from chips to NIS
            final_amount_nis = participation.final_amount * game.chips_value
            buy_in_nis = participation.buy_in * game.chips_value
            profit = final_amount_nis - buy_in_nis
            balances[player.name] += profit
    
    return render_template('monthly_summary.html', balances=balances)

@app.route('/end_month', methods=['POST'])
@login_required
def end_month():
    try:
        # Get all games from the current month that aren't already archived
        current_month = datetime.utcnow().month
        current_year = datetime.utcnow().year
        
        games = GameSession.query.filter(
            db.extract('month', GameSession.date) == current_month,
            db.extract('year', GameSession.date) == current_year,
            GameSession.is_archived == False
        ).all()
        
        # Archive all games
        for game in games:
            game.is_archived = True
        
        db.session.commit()
        flash('Month ended successfully. All games have been archived.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error ending month: {str(e)}')
    
    return redirect(url_for('monthly_summary'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        
        if not group_name:
            flash('Please provide a group name')
            return redirect(url_for('create_group'))

        # Create group with random join code
        join_code = secrets.token_urlsafe(8)
        group = Group(
            name=group_name,
            join_code=join_code,
            owner_id=current_user.id
        )
        db.session.add(group)
        db.session.commit()

        # Update current user
        current_user.group_id = group.id
        current_user.is_group_owner = True
        current_user.is_group_admin = True
        
        # Create player for the user if they don't have one
        if not current_user.player:
            player = Player(
                name=current_user.username,
                group_id=group.id,
                user_id=current_user.id
            )
            db.session.add(player)
        
        # Create approved membership record
        membership = GroupMembership(
            user_id=current_user.id,
            group_id=group.id,
            status='approved',
            date_requested=datetime.utcnow(),
            date_processed=datetime.utcnow()
        )
        db.session.add(membership)
        db.session.commit()

        flash('Group created successfully!')
        return redirect(url_for('index'))

    return render_template('create_group.html')

@app.route('/manage_group')
@login_required
def manage_group():
    if not (current_user.is_group_owner or current_user.is_group_admin or current_user.is_super_admin):
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))

    group = current_user.group
    pending_users = User.query.filter_by(group_id=group.id, is_approved=False).all()
    approved_users = User.query.filter_by(group_id=group.id, is_approved=True).all()

    return render_template('manage_group.html', 
                         group=group, 
                         pending_users=pending_users, 
                         approved_users=approved_users)

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not (current_user.is_group_owner or current_user.is_group_admin or current_user.is_super_admin):
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    if user.group_id != current_user.group_id:
        flash('Access denied. User not in your group.')
        return redirect(url_for('manage_group'))

    user.is_approved = True
    
    # Create player for the approved user
    player = Player(
        name=user.username,
        group_id=user.group_id,
        user_id=user.id
    )
    db.session.add(player)
    db.session.commit()
    
    flash(f'User {user.username} has been approved.')
    return redirect(url_for('manage_group'))

@app.route('/toggle_group_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_group_admin(user_id):
    if not (current_user.is_group_owner or current_user.is_super_admin):
        flash('Access denied. Only group owners can manage admin privileges.')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    if user.group_id != current_user.group_id:
        flash('Access denied. User not in your group.')
        return redirect(url_for('manage_group'))

    if user.is_group_owner or user.is_super_admin:
        flash('Cannot modify admin status of group owners or super admins.')
        return redirect(url_for('manage_group'))

    user.is_group_admin = not user.is_group_admin
    db.session.commit()
    flash(f'Admin privileges for {user.username} have been {"granted" if user.is_group_admin else "revoked"}.')
    return redirect(url_for('manage_group'))

@app.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
def remove_user(user_id):
    if not (current_user.is_group_owner or current_user.is_super_admin):
        flash('Access denied. Only group owners can remove users.')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    if user.group_id != current_user.group_id:
        flash('Access denied. User not in your group.')
        return redirect(url_for('manage_group'))

    if user.is_group_owner or user.is_super_admin:
        flash('Cannot remove group owners or super admins.')
        return redirect(url_for('manage_group'))

    if user.id == current_user.id:
        flash('You cannot remove yourself.')
        return redirect(url_for('manage_group'))

    # Delete the user's player record first
    if user.player:
        db.session.delete(user.player)
    
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been removed from the group.')
    return redirect(url_for('manage_group'))

@app.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    if request.method == 'POST':
        join_code = request.form.get('join_code')
        if not join_code:
            flash('Please provide a join code.', 'error')
            return redirect(url_for('join_group'))
        
        group = Group.query.filter_by(join_code=join_code).first()
        if not group:
            flash('Invalid join code. Please check and try again.', 'error')
            return redirect(url_for('join_group'))
        
        # Check if user already has a pending or approved membership
        existing_membership = GroupMembership.query.filter_by(
            user_id=current_user.id,
            group_id=group.id
        ).first()
        
        if existing_membership:
            if existing_membership.status == 'pending':
                flash('You already have a pending request to join this group.', 'info')
            elif existing_membership.status == 'approved':
                flash('You are already a member of this group.', 'info')
            else:
                flash('Your previous request was rejected. Please contact the group admin.', 'error')
            return redirect(url_for('index'))
        
        # Create new pending membership
        membership = GroupMembership(
            user_id=current_user.id,
            group_id=group.id,
            status='pending'
        )
        db.session.add(membership)
        db.session.commit()
        
        flash('Your request to join the group has been submitted. Please wait for admin approval.', 'success')
        return redirect(url_for('index'))
    
    return render_template('join_group.html')

@app.route('/approve_member/<int:membership_id>', methods=['POST'])
@login_required
def approve_member(membership_id):
    membership = GroupMembership.query.get_or_404(membership_id)
    
    # Check if current user has permission to approve
    if not (current_user.is_super_admin or 
            (current_user.group_id == membership.group_id and 
             (current_user.is_group_owner or current_user.is_group_admin))):
        flash('You do not have permission to approve members.', 'error')
        return redirect(url_for('manage_group'))
    
    membership.status = 'approved'
    membership.date_processed = datetime.utcnow()
    membership.user.group_id = membership.group_id  # Set the user's active group
    
    # Create a player record for the user
    player = Player(
        name=membership.user.username,
        user_id=membership.user.id,
        group_id=membership.group_id
    )
    
    db.session.add(player)
    db.session.commit()
    
    flash(f'User {membership.user.username} has been approved and added to the group.', 'success')
    return redirect(url_for('manage_group'))

@app.route('/reject_member/<int:membership_id>', methods=['POST'])
@login_required
def reject_member(membership_id):
    membership = GroupMembership.query.get_or_404(membership_id)
    
    # Check if current user has permission to reject
    if not (current_user.is_super_admin or 
            (current_user.group_id == membership.group_id and 
             (current_user.is_group_owner or current_user.is_group_admin))):
        flash('You do not have permission to reject members.', 'error')
        return redirect(url_for('manage_group'))
    
    membership.status = 'rejected'
    membership.date_processed = datetime.utcnow()
    db.session.commit()
    
    flash(f'User {membership.user.username} has been rejected.', 'success')
    return redirect(url_for('manage_group'))

@app.route('/view_group/<int:group_id>')
@login_required
def view_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if user has access to this group
    if current_user.group_id != group_id and not current_user.is_super_admin:
        flash('Access denied. You can only view your own group.')
        return redirect(url_for('index'))
    
    players = Player.query.filter_by(group_id=group_id).all()
    games = GameSession.query.filter_by(group_id=group_id, is_archived=False).all()
    
    # Calculate player statistics
    player_stats = {}
    for player in players:
        # Initialize stats for this player
        player_stats[player.id] = {
            'name': player.name,
            'total_games': 0,
            'total_buy_in': 0,
            'current_balance': 0
        }
        
        # Calculate totals from game participations
        for participation in player.game_participations:
            game = participation.game
            if not game.is_archived:
                player_stats[player.id]['total_games'] += 1
                
                # Convert chips to NIS for buy-in and final amount
                buy_in_nis = participation.buy_in * game.chips_value
                final_amount_nis = participation.final_amount * game.chips_value
                
                player_stats[player.id]['total_buy_in'] += buy_in_nis
                player_stats[player.id]['current_balance'] += (final_amount_nis - buy_in_nis)
    
    return render_template('view_group.html', 
                         group=group, 
                         players=players,
                         games=games,
                         player_stats=player_stats)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_super_admin:
        flash('Access denied. Super admin privileges required.')
        return redirect(url_for('index'))
    
    groups = Group.query.all()
    users = User.query.all()
    
    return render_template('admin_dashboard.html', groups=groups, users=users)

@app.route('/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    if not (current_user.is_group_owner or current_user.is_group_admin or current_user.is_super_admin):
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    if user.group_id != current_user.group_id and not current_user.is_super_admin:
        flash('Access denied. User not in your group.')
        return redirect(url_for('manage_group'))

    if user.is_approved or user.is_group_owner or user.is_super_admin:
        flash('Cannot reject approved users, group owners, or super admins.')
        return redirect(url_for('manage_group'))

    # Delete the user since they were rejected
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} has been rejected and removed.')
    return redirect(url_for('manage_group'))

def init_db():
    with app.app_context():
        # Create all tables if they don't exist
        db.create_all()
        
        # Create default group if it doesn't exist
        default_group = Group.query.filter_by(name='Default Group').first()
        if not default_group:
            default_group = Group(
                name='Default Group',
                join_code=secrets.token_urlsafe(8)
            )
            db.session.add(default_group)
            db.session.commit()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                group_id=default_group.id,
                is_super_admin=True,
                is_group_owner=True,
                is_group_admin=True,
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 