import React, { useState, useEffect } from 'react';
import axios from 'axios';
import AppAlertItem from './AppAlertItem.js';
import '../../assets/MyApps.scss';
import '../../assets/Error.scss';
import { Agent } from 'https';
import certs from '../../Certs/certs.js';
import ReactPaginate from 'react-paginate';

function MyAppsAlerts() {
	const [apps, setApps] = useState([]);
	const [selectAll, setSelectAll] = useState(false);
	const [errorMessage, setErrorMessage] = useState('');
	const [searchInput, setSearchInput] = useState('');
	const [typeInput, setTypeInput] = useState('');
	const [sortQueryInput, setSortQueryInput] = useState('')
	const [timestampInput, setTimestampInput] = useState('');
	const [selectedFilterType, setSelectedFilterType] = useState('normal');
	const [itemOffset, setItemOffset] = useState(0);
	const [pageCount, setPageCount] = useState(0);
	const [timestampOn, setTimeStampOn] = useState(false);

	const timeRanges = {
		"1 day": "1day",
		"3 days": "3day",
		"7 days": "7day",
		"14 days": "14day",
		"30 days": "30day",
		"60 days": "60day",
		"90 days": "90day"
	};

	// pagination
	const itemsPerPage = 5;

	const handlePageClick = (event) => {
		const selectedPage = event.selected;
		const newOffset = selectedPage * itemsPerPage;
		setItemOffset(newOffset);
	};

	const toggleAppSelection = (appId, isSelected) => {
		if (appId === 'all') {
			setSelectAll(isSelected);
			setApps(prevApps =>
				prevApps.map(app => ({
					...app,
					isSelected: isSelected
				}))
			);
		} else {
			setApps(prevApps =>
				prevApps.map(app =>
					app.name === appId ? { ...app, isSelected: isSelected } : app
				)
			);
		}
	};

	const buildAppConfig = (userInfo, query_my_apps, username) => ({
		headers: {
			'Content-type': 'application/json',
			'Accept-Encoding': 'gzip',
			'USER-AUTH': userInfo?.role,
			'USER-UUID': userInfo?.user_id,
		},
		params: {
			appnames: query_my_apps,
			username,
		},
	});

	const buildSearchConfig = (config_app, typeInput, searchInput, sortQueryInput) => {
		setTimeStampOn(typeInput === 'created_timestamp' || typeInput === 'updated_timestamp');

		if (selectedFilterType == 'normal') {
			if (typeInput === 'created_timestamp' || typeInput === 'updated_timestamp') {
				config_app.params.filter = `${typeInput}>='${timeRanges[timestampInput]}'`;
			} else {
				if (searchInput.length !== 0) {
					config_app.params.filter = `${typeInput}='${searchInput}'`
				}
			}
		} else {

			config_app.params = {
				...config_app.params,
				'filter': searchInput,
			};
		}

		if (sortQueryInput.length !== 0) {
			config_app.params.sort = sortQueryInput;
		}

		return config_app;
	};

	const buildPaginationConfig = (config_app, limitInput, offsetInput) => {
		config_app.params.limit = limitInput
		config_app.params.offset = offsetInput
		return config_app
	}

	const fetchApps = async () => {
		const userInfo = JSON.parse(localStorage.getItem('userInfo'));
		const username = userInfo?.username;

		const agent = new Agent({
			rejectUnauthorized: false,
			cert: certs.certFile,
			key: certs.keyFile,
		});
		const userConfig = {
			headers: {
				'Content-type': 'application/json',
				"Accept-Encoding": "gzip",
				'USER-AUTH': userInfo?.role,
				'USER-UUID': userInfo?.user_id,
			}
		};
		const responseUser = await axios.get(`https://localhost:9443/user/${username}`, userConfig, { httpsAgent: agent });

		const my_apps = responseUser.data?.applications;

		if (my_apps !== undefined) {
			const query_my_apps = my_apps.join();
			let config_app = buildAppConfig(userInfo, query_my_apps, username);
			config_app = buildSearchConfig(config_app, typeInput, searchInput, sortQueryInput);
			config_app = buildPaginationConfig(config_app, itemsPerPage, itemOffset)
			const responseApps = await axios.get('https://localhost:9443/app', config_app, { httpsAgent: agent });
			const errors = responseApps.data.Errors
			if (errors.length > 0) {
				setErrorMessage(`Could not retrieve your apps. Error : ` + errors[0].message);
				setApps([]);
			} else {
				setApps(responseApps.data.Response);
				setPageCount(Math.ceil(responseApps.data.QueryInfo.total / itemsPerPage));
				setErrorMessage();
			}
		}
	};

	useEffect(() => {
		fetchApps();
	}, [itemOffset, pageCount]);

	const renderApps = () => {
		if (apps) {
			return apps.map((app, i) => (
				<AppAlertItem
					key={i}
					app={app}
					onSelect={toggleAppSelection}
					isSelected={app.isSelected || selectAll}
				/>
			));
		}
	};

	return (
		<div className='myapps_container'>

			<div className="table-container" id='container'>
				<table className="table">
					<thead>
						<tr>
							<th>&nbsp;</th>
							<th>App Name</th>
							<th>Description</th>
							<th>Status</th>
							<th>CreatedTimestamp</th>
							<th>UpdatedTimestamp</th>
							<th>ScheduleType</th>
							<th>Port</th>
							<th>IPAddress</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{renderApps()}
					</tbody>
				</table>
				<ReactPaginate
					breakLabel="..."
					nextLabel="next >"
					onPageChange={(e) => handlePageClick(e)}
					pageCount={pageCount}
					previousLabel="< previous"
					renderOnZeroPageCount={null}
					activeClassName="item active-page"
					breakClassName='item break-me'
					containerClassName='pagination'
					disabledClassName='disabled-page'
					nextClassName='item next'
					previousClassName='item previous'
				/>
			</div>
			{errorMessage && <div className="error-message"> <span className="error-text">{errorMessage}</span> </div>}
		</div>

	);
}

export default MyAppsAlerts;
