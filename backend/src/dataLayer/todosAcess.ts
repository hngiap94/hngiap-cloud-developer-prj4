import * as AWS from 'aws-sdk'
// import * as AWSXRay from 'aws-xray-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'
import { createLogger } from '../utils/logger'
import { TodoItem } from '../models/TodoItem'
import { TodoUpdate } from '../models/TodoUpdate';

const AWSXRay = require('aws-xray-sdk')
const XAWS = AWSXRay.captureAWS(AWS)

const logger = createLogger('TodosAccess');

export class TodosAccess {
  constructor(
    private readonly docClient: DocumentClient = new XAWS.DynamoDB.DocumentClient(),
    private readonly todosTable = process.env.TODOS_TABLE,
    private readonly todosIndex = process.env.TODOS_CREATED_AT_INDEX
  ) { }

  async getTodosByUserId(userId: string): Promise<TodoItem[]> {
    logger.info(`todoAccess - getTodosForUser!!!`);

    const result = await this.docClient
      .query({
        TableName: this.todosTable,
        IndexName: this.todosIndex,
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
          ':userId': userId
        }
      })
      .promise();

    const items = result.Items;
    logger.info(`todoAccess - getTodosForUser - items: ${items}`);

    return items as TodoItem[];
  }

  async createNewTodo(todoItem: TodoItem): Promise<TodoItem> {
    logger.info(`todoAccess - createNewTodo!!!`);

    await this.docClient
      .put({
        TableName: this.todosTable,
        Item: todoItem
      })
      .promise();

    return todoItem as TodoItem;
  }

  async updateTodo(
    userId: string,
    todoId: string,
    updatedTodo: TodoUpdate
  ): Promise<TodoItem> {
    logger.info(`todoAccess - updateTodo!!!`);

    let params = {
      TableName: this.todosTable,
      Key: {
        userId,
        todoId
      },
      UpdateExpression: 'set #name = :name, #dueDate = :dueDate, #done = :done',
      ExpressionAttributeNames: {
        '#name': 'name',
        '#dueDate': 'dueDate',
        '#done': 'done'
      },
      ExpressionAttributeValues: {
        ':name': updatedTodo.name,
        ':dueDate': updatedTodo.dueDate,
        ':done': updatedTodo.done
      },
      ReturnValues: 'ALL_NEW'
    };
    logger.info(`todoAccess - updateTodo - params: ${params}`);

    const result = await this.docClient.update(params).promise();
    const item = result.Attributes;

    return item as TodoItem;
  }

  async deleteTodo(userId: string, todoId: string): Promise<TodoItem> {
    logger.info(`todoAccess - deleteTodo!!!`);

    let params = {
      TableName: this.todosTable,
      Key: {
        userId,
        todoId
      }
    };
    logger.info(`todoAccess - deleteTodo - params: ${params}`);

    const result = await this.docClient.delete(params).promise();
    const item = result.Attributes;

    return item as TodoItem;
  }

  async updateTodoAttachmentUrl(
    userId: string,
    todoId: string,
    attachmentUrl: string
  ): Promise<TodoItem> {
    logger.info(`todoAccess - updateTodoAttachmentUrl!!!`);

    const params = {
      TableName: this.todosTable,
      Key: {
        userId: userId,
        todoId: todoId
      },
      UpdateExpression: 'set #attachmentUrl = :attachmentUrl',
      ExpressionAttributeNames: {
        '#attachmentUrl': 'attachmentUrl'
      },
      ExpressionAttributeValues: {
        ':attachmentUrl': attachmentUrl
      },
      ReturnValues: 'ALL_NEW'
    };
    logger.info(`todoAccess - updateTodoAttachmentUrl - params: ${params}`);

    const result = await this.docClient.update(params).promise();
    const item = result.Attributes;
    return item as TodoItem;
  }
}