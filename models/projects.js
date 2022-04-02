const mongoose = require('mongoose');

const projects = new mongoose.Schema({
    username: { type: String, required: true },
    name: { type: String, required: true },
    description: { type: String, required: true },
    link: { type: String, required: true }
}, { collection: "projects" });

const model = mongoose.model('projects', projects);
module.exports = model;