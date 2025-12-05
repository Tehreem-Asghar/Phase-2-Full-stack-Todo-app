import uuid
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlmodel import Session, select, SQLModel
from pydantic import Field

from database import get_session
from models.task import Task
from models.user import User
from dependencies import get_current_user


router = APIRouter(prefix="/tasks", tags=["Tasks"])

class TaskCreate(SQLModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None)

class TaskRead(SQLModel):
    id: uuid.UUID
    title: str
    description: Optional[str]
    status: str
    user_id: uuid.UUID
    created_at: datetime # Add created_at
    updated_at: datetime # Add updated_at

@router.post("/", response_model=TaskRead, status_code=status.HTTP_201_CREATED)
async def create_task(
    task_data: TaskCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    task = Task(
        title=task_data.title,
        description=task_data.description,
        user_id=current_user.id
    )
    session.add(task)
    session.commit()
    session.refresh(task)
    return task

class TaskUpdate(SQLModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None)
    status: Optional[str] = Field(default=None, pattern="^(todo|in-progress|completed)$")


@router.put("/{task_id}", response_model=TaskRead)
async def update_task(
    task_id: uuid.UUID,
    task_update_data: TaskUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    task = session.exec(select(Task).where(Task.id == task_id)).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    if task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this task",
        )

    # Update fields from the request body
    update_data = task_update_data.model_dump(exclude_unset=True)
    task.sqlmodel_update(update_data)
    
    session.add(task)
    session.commit()
    session.refresh(task)
    return task


class Message(SQLModel):
    message: str

@router.delete("/{task_id}", response_model=Message)
async def delete_task(
    task_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    task = session.exec(select(Task).where(Task.id == task_id)).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    if task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this task",
        )

    session.delete(task)
    session.commit()
    return {"message": "Task deleted successfully"}



@router.get("/", response_model=List[TaskRead])
async def read_tasks(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    filter: Optional[str] = Query(None, pattern="^(all|todo|in-progress|completed)$"),
    sort: Optional[str] = Query("created_at", pattern="^(title|created_at)$") # Add sort query parameter
):
    query = select(Task).where(Task.user_id == current_user.id)

    if filter and filter != "all":
        query = query.where(Task.status == filter)
    
    if sort == "title":
        query = query.order_by(Task.title)
    elif sort == "created_at": # Default sort order is descending for created_at
        query = query.order_by(Task.created_at.desc()) # Default to newest first
        
    tasks = session.exec(query).all()
    return tasks

