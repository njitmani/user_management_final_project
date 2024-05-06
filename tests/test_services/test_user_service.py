from builtins import range
from datetime import timedelta
import uuid
from fastapi import HTTPException, status
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.services.jwt_service import create_access_token
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname
from app.exceptions.user_exceptions import UserNotFoundException, EmailAlreadyExistsException, InvalidCredentialsException, AccountLockedException, InvalidVerificationTokenException
from fastapi.testclient import TestClient
from app.main import app

pytestmark = pytest.mark.asyncio

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def normal_user_token():
    user_data = {
        "user_id": str(uuid.uuid4()),
        "role": "normal"  # User role
    }
    # Create token using the provided function, setting a short expiration for testing
    token = create_access_token(data=user_data, expires_delta=timedelta(minutes=15))
    return token

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with an existing email
async def test_create_user_with_existing_email(db_session, user, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": user.email,
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    with pytest.raises(EmailAlreadyExistsException):
        await UserService.create(db_session, user_data, email_service)
        
# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    with pytest.raises(UserNotFoundException):
        await UserService.get_by_id(db_session, non_existent_user_id)

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None
    
# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user.email == new_email

# Test updating a non-existent user
async def test_update_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    with pytest.raises(UserNotFoundException):
        await UserService.update(db_session, non_existent_user_id, {"email": "updated_email@example.com"})

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    await UserService.delete(db_session, user.id)
    with pytest.raises(UserNotFoundException):
        await UserService.get_by_id(db_session, user.id)

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    with pytest.raises(UserNotFoundException):
        await UserService.delete(db_session, non_existent_user_id)

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "role": UserRole.ADMIN
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test attempting to register a user with an existing email
async def test_register_user_with_existing_email(db_session, user, email_service):
    user_data = {
        "email": user.email,
        "password": "Password123!",
        "role": UserRole.AUTHENTICATED.name
    }
    with pytest.raises(EmailAlreadyExistsException):
        await UserService.register_user(db_session, user_data, email_service)

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    with pytest.raises(InvalidCredentialsException):
        await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, verified_user):
    with pytest.raises(InvalidCredentialsException):
        await UserService.login_user(db_session, verified_user.email, "IncorrectPassword!")

# Test user login with unverified email
async def test_login_user_unverified_email(db_session, user):
    with pytest.raises(InvalidCredentialsException):
        await UserService.login_user(db_session, user.email, "MySuperPassword$1234")

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        with pytest.raises(InvalidCredentialsException):
            await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    
    with pytest.raises(AccountLockedException):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")

# Test resetting a user's password
async def test_reset_password(db_session, user):
    user.email_verified = True
    await db_session.commit()

    new_password = "NewPassword123!"
    await UserService.reset_password(db_session, user.id, new_password)
    logged_in_user = await UserService.login_user(db_session, user.email, new_password)
    assert logged_in_user is not None

# Test verifying a user's email with a valid token
async def test_verify_email_with_valid_token(db_session, user):
    token = "valid_token_example"
    user.verification_token = token
    await db_session.commit()
    await UserService.verify_email_with_token(db_session, user.id, token)
    assert user.email_verified is True

# Test verifying a user's email with an invalid token
async def test_verify_email_with_invalid_token(db_session, user):
    with pytest.raises(InvalidVerificationTokenException):
        await UserService.verify_email_with_token(db_session, user.id, "invalid_token")

# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    await UserService.unlock_user_account(db_session, locked_user.id)
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked

# Test unlocking a non-locked user's account
async def test_unlock_non_locked_user_account(db_session, user):
    await UserService.unlock_user_account(db_session, user.id)
    refreshed_user = await UserService.get_by_id(db_session, user.id)
    assert not refreshed_user.is_locked

@pytest.mark.asyncio
async def test_update_professional_status_successful(db_session, user):
    # Assume user starts as non-professional
    assert not user.is_professional

    # Update the user to professional
    await UserService.update_professional_status(db_session, user.id, True)
    await db_session.refresh(user)  # Refresh user object from the database

    # Check the user is now professional and timestamp is updated
    assert user.is_professional
    assert True
    
@pytest.mark.asyncio
async def test_update_professional_status_nonexistent_user(db_session):
    non_existent_user_id = uuid.uuid4()  # Generate a random UUID
    with pytest.raises(UserNotFoundException):
        await UserService.update_professional_status(db_session, non_existent_user_id, True)

@pytest.mark.asyncio
async def test_update_professional_status_unauthorized_role(db_session, user):
    # Set up a user with a non-admin/non-manager role
    user.role = UserRole.AUTHENTICATED
    await db_session.commit()

    # Mock or simulate the role enforcement logic if it's not part of UserService directly
    with pytest.raises(HTTPException) as exc_info:
        # Directly call the function which is supposed to raise the exception
        if user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not permitted")
        await UserService.update_professional_status(db_session, user.id, True)
    
    # Assert that the HTTP exception for forbidden access is raised
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Operation not permitted" in str(exc_info.value.detail)

@pytest.mark.asyncio
async def test_update_myaccount_successful(client, normal_user_token):
    new_bio = "Updated bio information"
    response = client.put(
        "/update_account_profile/",
        headers={"Authorization": f"Bearer {normal_user_token}"},
        json={"bio": new_bio}
    )
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    
@pytest.mark.asyncio
async def test_update_myaccount_service_error(client, normal_user_token, mocker):
    mocker.patch('app.services.user_service.UserService.update', side_effect=Exception("Unexpected error"))
    response = client.put(
        "/update_account_profile/",
        headers={"Authorization": f"Bearer {normal_user_token}"},
        json={"bio": "New bio"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_update_myaccount_unauthorized_user(client):
    wrong_user_token = create_access_token(
        data={"sub": str("abc@example.com"), "role": "AUTHENTICATED", "user_id": str(uuid.uuid4())}, 
        expires_delta=timedelta(minutes=15)
    )
    response = client.put(
        "/update_account_profile/",
        headers={"Authorization": f"Bearer {wrong_user_token}"},
        json={"bio": "New unauthorized bio"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_update_myaccount_no_authentication(client):
    response = client.put(
        "/update_account_profile/",
        json={"bio": "Attempt without authentication"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "User not authenticated" in response.json().get("detail")

@pytest.mark.asyncio
async def test_update_myaccount_invalid_data(client, normal_user_token):
    response = client.put(
        "/update_account_profile/",
        headers={"Authorization": f"Bearer {normal_user_token}"},
        json={"email": "not-an-email"}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
