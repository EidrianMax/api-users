export default async function findAllUsers (collection) {
  const users = await collection.find().toArray()

  return users
}
