from datetime import date

def calculate_water_goal(user):
    # 1. Gender baseline (with fallback)
    if user.gender == "male":
        gender_base = 3700
    elif user.gender == "female":
        gender_base = 2700
    else:
        gender_base = 3200   # neutral fallback if not provided

    # 2. Weight factor
    weight = user.weight if user.weight is not None else 70 # fallback weight in kg
    weight_water = weight * 30

    # 3. Combine weight + gender
    base_water = (gender_base + weight_water) / 2

    # 4. Activity adjustment
    activity_water = 0
    if user.person_activity == "low":
        activity_water = 0
    elif user.person_activity == "moderate":
        activity_water = 500
    elif user.person_activity == "high":
        activity_water = 1000

    # 5. Climate adjustment
    climate_water = 0
    if user.climate == "cold":
        climate_water = 0
    elif user.climate == "mid":
        climate_water = 200
    elif user.climate == "hot":
        climate_water = 500

    # 6. Age adjustment
    age_water = 0
    if user.date_of_birth:
        today = date.today()
        age = today.year - user.date_of_birth.year - ((today.month, today.day) < (user.date_of_birth.month, user.date_of_birth.day))
        if age >= 55:
            age_water = -200
    
    # FINAL
    total_water = base_water + activity_water + climate_water + age_water
    
    return int(total_water)
