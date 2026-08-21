from database import engine, Base
from models import User, SurveyResponse, ExperimentResult, Message

Base.metadata.create_all(bind=engine)