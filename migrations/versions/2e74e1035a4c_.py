"""empty message

Revision ID: 2e74e1035a4c
Revises: 37b1373903c8
Create Date: 2022-01-29 14:11:09.308557

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '2e74e1035a4c'
down_revision = '37b1373903c8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('article', sa.Column('poster_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'article', 'users', ['poster_id'], ['id'])
    op.drop_column('article', 'author')
    op.create_unique_constraint(None, 'users', ['username'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.add_column('article', sa.Column('author', mysql.VARCHAR(length=255), nullable=True))
    op.drop_constraint(None, 'article', type_='foreignkey')
    op.drop_column('article', 'poster_id')
    # ### end Alembic commands ###
