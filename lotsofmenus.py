from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Menu, Base, MenuItem, User

engine = create_engine('sqlite:///menuwithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Amit Sharma", email="sharmaamit92@hotmail.com",
             picture='')
session.add(User1)
session.commit()

# Menu for UrbanBurger
menu1 = Menu(user_id=1, name="Hockey")

session.add(menu1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="stick", description="it is a hockey stick",
                      menu_id=menu1.id)

session.add(menuItem2)
session.commit()





print "added menu items!"
