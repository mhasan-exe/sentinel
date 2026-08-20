from database import engine, Base
from models import User, SurveyResponse, ExperimentResult

Base.metadata.create_all(bind=engine)