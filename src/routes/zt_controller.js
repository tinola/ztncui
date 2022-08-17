/*
  ztncui - ZeroTier network controller UI
  Copyright (C) 2017-2021  Key Networks (https://key-networks.com)
  Licensed under GPLv3 - see LICENSE for details.
*/

const express = require('express');
const { restrict, restrictSuperAdmin, restrictNetwork } = require('../controllers/auth');
const router = express.Router();

var networkController = require('../controllers/networkController');

// network routes //

// GET ZT network controller home page
router.get('/', restrict, networkController.index);

// Get request for creating a network
router.get('/network/create', restrict, restrictSuperAdmin, networkController.network_create_get);

// POST request for creating a network
router.post('/network/create', restrict, restrictSuperAdmin, networkController.network_create_post);

// GET request to delete network
router.get('/network/:nwid/delete', restrict, restrictNetwork, networkController.network_delete_get);

// POST request to delete network
router.post('/network/:nwid/delete', restrict, restrictNetwork, networkController.network_delete_post);

// POST request for Network name
router.post('/network/:nwid/name', restrict, restrictNetwork, networkController.name);

// GET request for ipAssignmentPool delete
router.get('/network/:nwid/ipAssignmentPools/:ipRangeStart/:ipRangeEnd/delete', restrict, restrictNetwork, networkController.ipAssignmentPool_delete);

// POST request for ipAssignmentPools
router.post('/network/:nwid/ipAssignmentPools', restrict, restrictNetwork, networkController.ipAssignmentPools);

// GET request for route delete
router.get('/network/:nwid/routes/:target_ip/:target_prefix/delete', restrict, restrictNetwork, networkController.route_delete);

// POST request for routes
router.post('/network/:nwid/routes', restrict, restrictNetwork, networkController.routes);

// POST request for dns
router.post('/network/:nwid/dns', restrict, restrictNetwork, networkController.dns);

// POST request for private
router.post('/network/:nwid/private', restrict, restrictNetwork, networkController.private);

// POST request for v4AssignMode
router.post('/network/:nwid/v4AssignMode', restrict, restrictNetwork, networkController.v4AssignMode);

// POST request for v6AssignMode
router.post('/network/:nwid/v6AssignMode', restrict, restrictNetwork, networkController.v6AssignMode);

// GET request for member delete
router.get('/network/:nwid/member/:id/delete', restrict, restrictNetwork, networkController.member_delete);

// POST request for member delete
router.post('/network/:nwid/member/:id/delete', restrict, restrictNetwork, networkController.member_delete);

// GET request for any member object
router.get('/network/:nwid/member/:id/:object', restrict, restrictNetwork, networkController.member_object);

// GET request for member detail
router.get('/network/:nwid/member/:id', restrict, restrictNetwork, networkController.member_detail);

// GET request for easy network setup
router.get('/network/:nwid/easy', restrict, restrictNetwork, networkController.easy_get);

// POST request for easy network setup
router.post('/network/:nwid/easy', restrict, restrictNetwork, networkController.easy_post);

// GET request for easy member (de)authorization
router.get('/network/:nwid/members', restrict, restrictNetwork, networkController.members);

// POST request for easy member (de)authorization
router.post('/network/:nwid/members', restrict, restrictNetwork, networkController.members);

// GET request for member ipAssignment delete
router.get('/network/:nwid/member/:id/ipAssignments/:index/delete', restrict, restrictNetwork, networkController.delete_ip);

// POST request for member ipAssignment add
router.post('/network/:nwid/member/:id/ipAssignments', restrict, restrictNetwork, networkController.assign_ip);


// GET request for any network object
router.get('/network/:nwid/:object', restrict, restrictNetwork, networkController.network_object);

// GET request for one network
router.get('/network/:nwid', restrict, restrictNetwork, networkController.network_detail);

// GET request for list of all networks
router.get('/networks', restrict, networkController.network_list);

module.exports = router;
