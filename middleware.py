from fastapi import HTTPException, Depends
from jose import JWTError, jwt
from dependencies import oauth2_scheme, SECRET_KEY, ALGORITHM, get_db
import logging
import mysql.connector

logger = logging.getLogger(__name__)

async def role_required(role: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_role_id = payload.get("role_id")
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT name FROM roles WHERE id = %s", (user_role_id,))
        user_role = cursor.fetchone()[0]
        if user_role != role:
            logger.warning(f"Unauthorized access attempt by user with role {user_role}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource",
            )
    except JWTError:
        logger.warning("Invalid or expired token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    except mysql.connector.Error as e:
        logger.error(f"Database error in role_required middleware: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {e}",
        )
    finally:
        cursor.close()
        db.close()