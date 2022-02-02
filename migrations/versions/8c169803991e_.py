"""empty message

Revision ID: 8c169803991e
Revises: 282a3a88ebe6
Create Date: 2022-01-31 13:03:23.396661

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '8c169803991e'
down_revision = '282a3a88ebe6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'users', ['username'])
    op.drop_column('users', 'profile_picture')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('profile_picture', mysql.VARCHAR(length=500), nullable=True))
    op.drop_constraint(None, 'users', type_='unique')
    # ### end Alembic commands ###
