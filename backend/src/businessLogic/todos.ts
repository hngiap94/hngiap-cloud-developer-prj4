import { TodosAccess } from '../dataLayer/todosAcess'
import { AttachmentUtils } from '../dataLayer/attachmentUtils';
import { TodoItem } from '../models/TodoItem'
import { CreateTodoRequest } from '../requests/CreateTodoRequest'
import { UpdateTodoRequest } from '../requests/UpdateTodoRequest'
import { createLogger } from '../utils/logger'
import * as uuid from 'uuid'
// import * as createError from 'http-errors'

const logger = createLogger('Todos');

const todosAccess = new TodosAccess();
const attachmentUtils = new AttachmentUtils();

export async function getTodosForUser(userId: string): Promise<TodoItem[]> {
    logger.info('todos - getTodosForUser!!!');
    return todosAccess.getTodosByUserId(userId);
}

export async function createTodo(
    createTodoRequest: CreateTodoRequest,
    userId: string
): Promise<TodoItem> {
    logger.info('todos - createTodo!!!');
  
    const todoId = uuid.v4();
    const createdAt = new Date().toISOString();
    const newItem = {
      userId,
      todoId,
      createdAt,
      done: false,
      attachmentUrl: null,
      ...createTodoRequest
    };

    logger.info(`todos - createTodo - newItem: ${newItem}`);
  
    return await todosAccess.createNewTodo(newItem);
}

export async function updateTodo(
    userId: string,
    todoId: string,
    todoUpdate: UpdateTodoRequest
): Promise<UpdateTodoRequest> {
    logger.info('todos - updateTodo!!!');
    return await todosAccess.updateTodo(userId, todoId, todoUpdate);
}

export async function deleteTodo(
    userId: string,
    todoId: string
): Promise<TodoItem> {
    logger.info('todos - deleteTodo!!!');
    return todosAccess.deleteTodo(userId, todoId);
}

export async function createAttachmentPresignedUrl(
    userId: string,
    todoId: string
) {
    logger.info('todos - createAttachmentPresignedUrl!!!');

    const signedUrl = await attachmentUtils.getSignedUrl(todoId);
    logger.info(`todos - createAttachmentPresignedUrl - signedUrl: ${signedUrl}`);

    const s3AttachmentUrl = attachmentUtils.generateS3AttachmentUrl(todoId);
    logger.info(`todos - createAttachmentPresignedUrl - s3AttachmentUrl: ${s3AttachmentUrl}`);

    await todosAccess.updateTodoAttachmentUrl(userId, todoId, s3AttachmentUrl);

    return signedUrl;
}