export default async function createUser (collection, body) {
  return await collection.insertOne(body)
}
